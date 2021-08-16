package se.sics.ace.oscore.group;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.oscore.rs.OscoreAuthzInfoGroupOSCORE;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.TokenRepository;

/**
 * A RS for testing the OSCORE profile of ACE (https://datatracker.ietf.org/doc/draft-ietf-ace-oscore-profile)
 * 
 * Server for testing Group Joining over OSCORE.
 * Should first receive a Token to authz-info.
 * 
 * Followed by a request to initiate the Join procedure,
 * the server will reply with the Join response.
 * 
 * @author Marco Tiloca and Rikard Hoeglund
 *
 */
public class TestOscorepRSGroupOSCORE {
	
	//Sets the port to use
	private final static int PORT = CoAP.DEFAULT_COAP_PORT;
	
    private final static String rootGroupMembershipResource = "ace-group";
	
	// Up to 4 bytes, same for all the OSCORE Group of the Group Manager
	private final static int groupIdPrefixSize = 4; 
	
	private final static String prefixMonitorNames = "M"; // Initial part of the node name for monitors, since they do not have a Sender ID
	
	private final static String nodeNameSeparator = "-"; // For non-monitor members, separator between the two components of the node name
	
	private static Set<Integer> validRoleCombinations = new HashSet<Integer>();
	
	private static Map<String, GroupInfo> activeGroups = new HashMap<>();
	
	private static Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
	
	private static GroupOSCOREJoinValidator valid = null;

    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {
            
            // set resource identifier
            super("helloWorld");
            
            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("Hello World!");
        }
    }
    
    /**
     * Definition of the Manage Resource
     */
    public static class ManageResource extends CoapResource {
        
        /**
         * Constructor
         */
        public ManageResource() {
            
            // set resource identifier
            super("manage");
            
            // set display name
            getAttributes().setTitle("Manage Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("This is the /manage resource.");
        }
        
        @Override
        public void handlePOST(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("This is the /manage resource.");
        }
    }
    
    
    /**
     * Definition of the Temp Resource
     */
    public static class TempResource extends CoapResource {
        
        /**
         * Constructor
         */
        public TempResource() {
            
            // set resource identifier
            super("temp");
            
            // set display name
            getAttributes().setTitle("Temp Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("19.0 C");
        }
    }
    
    private static OscoreAuthzInfoGroupOSCORE ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;  
    
    /**
     * The CoAP OSCORE server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 1);
    	Security.insertProviderAt(EdDSA, 0);
    	
        // Set the valid combinations of roles in a Joining Request
        // Combinations are expressed with the AIF specific data model AIF-OSCORE-GROUPCOMM
        validRoleCombinations.add(1 << Constants.GROUP_OSCORE_REQUESTER); // Requester (2)
        validRoleCombinations.add(1 << Constants.GROUP_OSCORE_RESPONDER); // Responder (4)
        validRoleCombinations.add(1 << Constants.GROUP_OSCORE_MONITOR); // Monitor (8)
        validRoleCombinations.add((1 << Constants.GROUP_OSCORE_REQUESTER) +
        		                  (1 << Constants.GROUP_OSCORE_RESPONDER)); // Requester+Responder (6)
    	
    	final String groupName = "feedca570000";
    	
    	// Uncomment to set ECDSA with curve P-256 for countersignatures
        // int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
        
        // Uncomment to set EDDSA with curve Ed25519 for countersignatures
        int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
        
  	    // Uncomment to set curve P-256 for pairwise key derivation
  	    // int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
  	    
  	    // Uncomment to set curve X25519 for pairwise key derivation
  	    int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();
 
        // Set up token repository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        myScopes.put("r_helloWorld", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        // Adding the group-membership resource, with group name "feedca570000".
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResource, actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.POST);
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/pub-key", actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/gm-pub-key", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/verif-data", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/num", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/active", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/policies", actions3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource3);
        
        // Adding another group-membership resource, with group name "fBBBca570000".
        // There will NOT be a token enabling the access to this resource.
        Map<String, Set<Short>> myResource4 = new HashMap<>();
        Set<Short> actions4 = new HashSet<>();
        actions4.add(Constants.GET);
        actions4.add(Constants.POST);
        myResource4.put(rootGroupMembershipResource + "/" + "fBBBca570000", actions4);
        myScopes.put(rootGroupMembershipResource + "/" + "fBBBca570000", myResource4);

        Set<String> auds = new HashSet<>();
        auds.add("rs1"); // Simple test audience
        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResource);
        
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("rs2"));
        
        // Include the root group-membership resource for Group OSCORE.
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource));
        
        // For each OSCORE group, include the associated group-membership resource and its sub-resources
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/pub-key"));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/gm-pub-key"));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/verif-data"));        
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/num"));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/active"));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/policies"));
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        // Delete lingering old token files
        new File(tokenFile).delete();
        
        byte[] key128a 
            = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                   
        //Set up COSE parameters (enable for encrypting Tokens)
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        //Set up the inner Authz-Info library
        //Changed this OscoreAuthzInfo->OscoreAuthzInfoGroupOSCORE
        ai = new OscoreAuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                  new KissTime(), null, valid, ctx,
                  tokenFile, valid, false);
      
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(activeGroups);
      
        //Add a test token to authz-info
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
      
        byte[] kid  = new byte[] {0x01, 0x02, 0x03};
        CBORObject kidC = CBORObject.FromObject(kid);
        key.add(KeyKeys.KeyId, kidC);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx)); //Encrypting Token
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1); 
        payload.Add(Constants.CNONCE, n1);
      
        ai.processMessage(new LocalMessage(0, null, null, payload));

        AsRequestCreationHints archm = new AsRequestCreationHints(
                  "coaps://blah/authz-info/", null, false, false);
        Resource hello = new HelloWorldResource();
        Resource temp = new TempResource();
        Resource authzInfo = new CoapAuthzInfo(ai);
        
        // The root group-membership resource
  	    Resource groupOSCORERootMembership = new GroupOSCORERootMembershipResource(rootGroupMembershipResource);
  	    
  	    /*
  	     * For each OSCORE group, create the associated group-membership resource and its sub-resources
  	    */
        // Group-membership resource - The name of the OSCORE group is used as resource name
        Resource join = new GroupOSCOREJoinResource(groupName);
        // Add the /pub-key sub-resource
        Resource pubKeySubResource = new GroupOSCORESubResourcePubKey("pub-key");
        join.add(pubKeySubResource);
        // Add the /gm-pub-key sub-resource
        Resource gmPubKeySubResource = new GroupOSCORESubResourcePubKey("gm-pub-key");
        join.add(gmPubKeySubResource);
        // Add the /verif-data sub-resource
        Resource verifDataSubResource = new GroupOSCORESubResourcePubKey("verif-data");
        join.add(verifDataSubResource);
        
        // Add the /num sub-resource
        Resource numSubResource = new GroupOSCORESubResourceNum("num");
        join.add(numSubResource);
  	    // Add the /active sub-resource
        Resource activeSubResource = new GroupOSCORESubResourceActive("active");
  	    join.add(activeSubResource);
  	    // Add the /policies sub-resource
        Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies");
  	    join.add(policiesSubResource);
        // Add the /nodes sub-resource, as root to actually accessible per-node sub-resources
        Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes");
  	    join.add(nodesSubResource);
      
        //Create the OSCORE Group(s)
        if (!OSCOREGroupCreation(groupName, signKeyCurve))
        	return;
  	    
        rs = new CoapServer();
        rs.add(hello);
        rs.add(temp);
        rs.add(authzInfo);
  	    rs.add(groupOSCORERootMembership);
  	    groupOSCORERootMembership.add(join);

      
        rs.addEndpoint(new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(CoAP.DEFAULT_COAP_PORT)
                .setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance())
                .build());
      
        dpd = new CoapDeliverer(rs.getRoot(), null, archm); 
        // Add special allowance for Token and message from this OSCORE Sender ID

        rs.setMessageDeliverer(dpd);
        rs.start();
        System.out.println("OSCORE RS (GM) Server starting on port " + PORT);
      
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws AceException {
        rs.stop();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }

    /**
     * Definition of the root group-membership resource for Group OSCORE
     * 
     * Children of this resource are the group-membership resources
     */
    public static class GroupOSCORERootMembershipResource extends CoapResource {
        
        /**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORERootMembershipResource(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Resource " + resId);
        }
        
        @Override
        public void handleFETCH(CoapExchange exchange) {
        	System.out.println("FETCH request reached the GM");
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
            
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	if(requestPayload == null) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "A payload must be present");
        		return;
        	}
        	
        	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
			
        	// The payload of the request must be a CBOR Map
        	if (!requestCBOR.getType().equals(CBORType.Map)) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid payload format");
	    		return;
        	}
        	
        	// The CBOR Map must include exactly one element, i.e. 'gid'
        	if ((requestCBOR.size() != 1) || (!requestCBOR.ContainsKey(Constants.GID))) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid payload format");
	    		return;
        	}
        	
        	// The 'gid' element must be a CBOR array, with at least one element
        	if (requestCBOR.get(Constants.GID).getType() != CBORType.Array ||
        		requestCBOR.get(Constants.GID).size() == 0) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid payload format");
	    		return;
        	}
        	
        	// Each element of 'gid' element must be a CBOR byte string
        	for (int i = 0 ; i < requestCBOR.get(Constants.GID).size(); i++) {
	        	if (requestCBOR.get(Constants.GID).get(i).getType() != CBORType.ByteString) {
					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid payload format");
		    		return;
	        	}
        	}
        	    		
    		List<CBORObject> inputGroupIds = new ArrayList<CBORObject> ();
    		for (int i = 0; i < requestCBOR.get(Constants.GID).size(); i++) {
    			inputGroupIds.add(requestCBOR.get(Constants.GID).get(i));
    		}
    		
    		List<String> preliminaryGroupNames = new ArrayList<String>();
    		List<CBORObject> finalGroupNames = new ArrayList<CBORObject>();
    		List<CBORObject> finalGroupIds = new ArrayList<CBORObject>();
    		List<CBORObject> finalGroupURIs = new ArrayList<CBORObject>();
    		
    		// Navigate the list of existing OSCORE groups
        	for (String groupName : activeGroups.keySet()) {
        		
        		GroupInfo myGroup = activeGroups.get(groupName);
        		byte[] storedGid = myGroup.getGroupId();
        		
        		// Navigate the list of Group IDs specified in the request
        		for (int i = 0; i < inputGroupIds.size(); i ++) {
        			byte[] inputGid = inputGroupIds.get(i).GetByteString();
        			
        			// A match is found with the examined OSCORE group
        			if (Arrays.equals(storedGid, inputGid)) {
            			// Store the used Group Name for future inspection
        				preliminaryGroupNames.add(groupName);
        				// No need to further consider this Group ID value
        				inputGroupIds.remove(i);
        				break;
        			}
        		}
        		
        		if (inputGroupIds.isEmpty())
        			break;
        		
        	}
    		
        	// Check if the requesting client is a group member or an authorized Verifier
        	for (String groupName : preliminaryGroupNames) {
        		
        		GroupInfo targetedGroup = activeGroups.get(groupName);
        		
            	if (!targetedGroup.isGroupMember(subject)) {
            		
            		// The requester is not a current group member.
            		//
            		// This is still fine, as long as at least one Access Tokens
            		// of the requester allows also the role "Verifier" in this group
            		
            		// Check that at least one of the Access Tokens for this node allows (also) the Verifier role for this group
                	
            		int role = 1 << Constants.GROUP_OSCORE_VERIFIER;
            		boolean allowed = false;
                	int[] roleSetToken = getRolesFromToken(subject, groupName);
                	if (roleSetToken == null) {
                		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
                		return;
                	}
                	else {
                		for (int index = 0; index < roleSetToken.length; index++) {
                			if ((role & roleSetToken[index]) != 0) {
                    			// 'scope' in this Access Token admits (also) the role "Verifier" for this group. This makes it fine for the requester.
                				allowed = true;
                				break;
                			}
                		}
                	}
                	
                	// Move considering the next group
                	if (!allowed) {
                		continue;
                	}
                	
            	}
            	
            	finalGroupNames.add(CBORObject.FromObject(groupName));
            	byte[] gid = targetedGroup.getGroupId();
            	finalGroupIds.add(CBORObject.FromObject(gid));
            	finalGroupURIs.add(CBORObject.FromObject(this.getURI() + "/" + groupName));
            	
        	}
        	
            
            // Respond to the Group Name and URI Retrieval Request
            
        	byte[] responsePayload = null;
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	
        	// The response is an empty CBOR byte string
        	if (finalGroupNames.size() == 0) {
        		byte[] emptyArray = new byte[0];
        		responsePayload = CBORObject.FromObject(emptyArray).EncodeToBytes();
        	}
        	// The response is a CBOR may including three CBOR arrays
        	else {
        		CBORObject myResponse = CBORObject.NewMap();

        		CBORObject gnameArray = CBORObject.NewArray();
        		CBORObject gidArray = CBORObject.NewArray();
        		CBORObject guriArray = CBORObject.NewArray();
        		
        		for (int i = 0; i < finalGroupNames.size(); i++) {
        			gnameArray.Add(finalGroupNames.get(i));
        			gidArray.Add(finalGroupIds.get(i));
        			guriArray.Add(finalGroupURIs.get(i));
        		}
        		
        		myResponse.Add(Constants.GID, gidArray);
        		myResponse.Add(Constants.GNAME, gnameArray);
        		myResponse.Add(Constants.GURI, guriArray);
        		
        		responsePayload = myResponse.EncodeToBytes();
            	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        	} 
            
        	coapResponse.setPayload(responsePayload);

        	exchange.respond(coapResponse);
        	
        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership resource
     */
    public static class GroupOSCOREJoinResource extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCOREJoinResource(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Resource " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}  
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {	
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
            
        	// Respond to the Key Distribution Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	myResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	// Fill the 'key' parameter
        	// Note that no Sender ID is included
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.pub_key_enc, targetedGroup.getPubKeyEnc());
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
        		// The group mode is used
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg, targetedGroup.getSignEncAlg().AsCBOR());
            	myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
            	if (targetedGroup.getSignParams().size() != 0)
            		myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
        	}
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
        		// The pairwise mode is used
        		myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
            	myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
            	if (targetedGroup.getEcdhParams().size() != 0)
            		myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
        	}
        	myResponse.Add(Constants.KEY, myMap);
        	
        	// The current version of the symmetric keying material
        	myResponse.Add(Constants.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
        	
        	// CBOR Value assigned to the coap_group_oscore profile.
        	myResponse.Add(Constants.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(Constants.COAP_GROUP_OSCORE_APP));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	myResponse.Add(Constants.EXP, CBORObject.FromObject(1000000));

        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
        @Override
        public void handlePOST(CoapExchange exchange) {
            
        	System.out.println("POST request reached the GM");
        	
        	String groupName;
        	Set<String> roles = new HashSet<>();
        	boolean providePublicKeys = false;
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
            
            String rsNonceString = TokenRepository.getInstance().getRsnonce(subject);
            
            if(rsNonceString == null) {
            	// Return an error response, with a new nonce for PoP of the Client's private key in the next Join Request
        	    CBORObject responseMap = CBORObject.NewMap();
                byte[] rsnonce = new byte[8];
                new SecureRandom().nextBytes(rsnonce);
                responseMap.Add(Constants.KDCCHALLENGE, rsnonce);
                TokenRepository.getInstance().setRsnonce(subject, Base64.getEncoder().encodeToString(rsnonce));
                byte[] responsePayload = responseMap.EncodeToBytes();
            	exchange.respond(CoAP.ResponseCode.BAD_REQUEST, responsePayload, Constants.APPLICATION_ACE_CBOR);
            	return;
            }
                        
            byte[] rsnonce = Base64.getDecoder().decode(rsNonceString);
        	
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	if(requestPayload == null) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "A payload must be present");
        		return;
        	}
        	
        	CBORObject joinRequest = CBORObject.DecodeFromBytes(requestPayload);
        	
			CBORObject errorResponseMap = CBORObject.NewMap();
        	
        	// Prepare the 'sign_info' and 'ecdh_info' parameter, to possibly return it in a 4.00 (Bad Request) response        	
    		CBORObject signInfo = CBORObject.NewArray();
        	CBORObject ecdhInfo = CBORObject.NewArray();
				
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getName());
			
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	if (!targetedGroup.getStatus()) {
        		// The group is currently inactive and no new members are admitted
        		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "The OSCORE group is currently not active");
            	return;
        	}
        	
        	// The group mode is used
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
				CBORObject signInfoEntry = CBORObject.NewArray();
				signInfoEntry.Add(CBORObject.FromObject(targetedGroup.getGroupName())); // 'id' element
				signInfoEntry.Add(targetedGroup.getSignAlg().AsCBOR()); // 'sign_alg' element
		    	CBORObject arrayElem = targetedGroup.getSignParams().get(0); // 'sign_parameters' element (The algorithm capabilities)
		    	if (arrayElem == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(arrayElem);
		    	arrayElem = targetedGroup.getSignParams().get(1); // 'sign_key_parameters' element (The key type capabilities)
		    	if (arrayElem == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(arrayElem);
		    	signInfoEntry.Add(targetedGroup.getPubKeyEnc()); // 'pub_key_enc' element
			    signInfo.Add(signInfoEntry);
			    errorResponseMap.Add(Constants.SIGN_INFO, signInfo);
        	}
        	
        	// The pairwise mode is used
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
				CBORObject ecdhInfoEntry = CBORObject.NewArray();
				ecdhInfoEntry.Add(CBORObject.FromObject(targetedGroup.getGroupName())); // 'id' element
				ecdhInfoEntry.Add(targetedGroup.getEcdhAlg().AsCBOR()); // 'ecdh_alg' element
		    	CBORObject arrayElem = targetedGroup.getEcdhParams().get(0); // 'ecdh_parameters' element (The algorithm capabilities)
		    	if (arrayElem == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(arrayElem);
		    	arrayElem = targetedGroup.getEcdhParams().get(1); // 'ecdh_key_parameters' element (The key type capabilities)
		    	if (arrayElem == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(arrayElem);
		    	ecdhInfoEntry.Add(targetedGroup.getPubKeyEnc()); // 'pub_key_enc' element
			    ecdhInfo.Add(ecdhInfoEntry);
			    errorResponseMap.Add(Constants.ECDH_INFO, ecdhInfo);
        	}
		    
		    
        	// The payload of the join request must be a CBOR Map
        	if (!joinRequest.getType().equals(CBORType.Map)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
        	}
        		
        	// More steps follow:
        	//
        	// Retrieve 'scope' from the map; check the GroupID against the name of the resource, just for consistency.
        	//
        	// Retrieve the role(s) to possibly reduce the set of material to provide to the joining node.
        	//
        	// Any other check is performed through the method canAccess() of the TokenRepository, which is
        	// in turn invoked by the deliverRequest() method of CoapDeliverer, upon getting the join request.
        	// The actual checks of legitimate access are performed by scopeMatchResource() and scopeMatch()
        	// of the GroupOSCOREJoinValidator used as Scope/Audience Validator.
        	
        	// Retrieve scope
        	CBORObject scope = joinRequest.get(CBORObject.FromObject(Constants.SCOPE));
        	
        	// Scope must be included for joining OSCORE groups
        	if (scope == null) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
        	}
        	// Scope must be wrapped in a binary string for joining OSCORE groups
        	if (!scope.getType().equals(CBORType.ByteString)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
            }
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	// Invalid scope format for joining OSCORE groups
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
            }
        	
        	// Invalid scope format for joining OSCORE groups
        	if (cborScope.size() != 2) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
            }
        	
        	// Retrieve the name of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		groupName = scopeElement.AsString();

      	  		// The group name in 'scope' is not pertinent for this group-membership resource
      	  		if (!groupName.equals(this.getName())) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
	  				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
	  				return;
	  			}      	  		
      	  	}
      	  	// Invalid scope format for joining OSCORE groups
      	  	else {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
      	  	}
      	  	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	
      	  	int roleSet = 0;
      	  	
        	if (scopeElement.getType().equals(CBORType.Integer)) {
        		roleSet = scopeElement.AsInt32();
        		
        		// Invalid format of roles
        		if (roleSet < 0) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
      	  			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
	        		return;
        		}
     	  		// Invalid combination of roles
        		if(!validRoleCombinations.contains(roleSet)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
  					return;
        		}
        		Set<Integer> roleIdSet = new HashSet<Integer>();
        		try {
            		roleIdSet = Util.getGroupOSCORERoles(roleSet);
        		}
        		catch(AceException e) {
        			System.err.println(e.getMessage());
        		}
        		short[] roleIdArray = new short[roleIdSet.size()];
        		int index = 0;
        		for (Integer elem : roleIdSet)
        		    roleIdArray[index++] = elem.shortValue(); 
        		for (int i=0; i<roleIdArray.length; i++) {
        			short roleIdentifier = roleIdArray[i];
        			// Silently ignore unrecognized roles
        			if (roleIdentifier < Constants.GROUP_OSCORE_ROLES.length)
        				roles.add(Constants.GROUP_OSCORE_ROLES[roleIdentifier]);
        		}
        		  
        	}
      	  	
      	  	
        	// Invalid format of roles
      	  	else {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
      	  	}
        
        	// Check that the indicated roles for this group are actually allowed by the Access Token 
        	boolean allowed = false;
        	int[] roleSetToken = getRolesFromToken(subject, groupName);
        	if (roleSetToken == null) {
        		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
        		return;
        	}
        	else {
        		for (int index = 0; index < roleSetToken.length; index++) {
            		if ((roleSet & roleSetToken[index]) == roleSet) {
            			// 'scope' in at least one Access Token admits all the roles indicated for this group in the Joining Request
            			allowed = true;
            			break;
            		}
        		}	
        	}
        	
        	if (!allowed) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
        		return;
        	}
        	
        	// Retrieve 'get_pub_keys'
        	// If present, this parameter must be a CBOR array or the CBOR simple value Null
        	CBORObject getPubKeys = joinRequest.get(CBORObject.FromObject((Constants.GET_PUB_KEYS)));
        	if (getPubKeys != null) {
        		
        		// Invalid format of 'get_pub_keys'
        		if (!getPubKeys.getType().equals(CBORType.Array) && !getPubKeys.equals(CBORObject.Null)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
        		}

        		// Invalid format of 'get_pub_keys'
        		if (getPubKeys.getType().equals(CBORType.Array)) {
	        		if ( getPubKeys.size() != 3 ||
	        	        !getPubKeys.get(0).getType().equals(CBORType.Boolean) ||
	        	         getPubKeys.get(0).AsBoolean() != true ||
	        			!getPubKeys.get(1).getType().equals(CBORType.Array) ||
	        			!getPubKeys.get(2).getType().equals(CBORType.Array) || 
	        			 getPubKeys.get(2).size() != 0) {
	            		
	            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
	        			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
	            		return;
	            		
	        		}
        		}

        		// Invalid format of 'get_pub_keys'
        		if (getPubKeys.getType().equals(CBORType.Array)) {
	    			for (int i = 0; i < getPubKeys.get(1).size(); i++) {
	    				// Possible elements of the first array have to be all integers and
	    				// express a valid combination of roles encoded in the AIF data model
	    				if (!getPubKeys.get(1).get(i).getType().equals(CBORType.Integer) ||
	    					!validRoleCombinations.contains(getPubKeys.get(1).get(i).AsInt32())) {
	                		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
	            			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
	                		return;
	    					
	    				}
	    			}
        		}

        		providePublicKeys = true;
        		
        	}
        	
        	// Retrieve the entry for the target OSCORE group, using the group name
        	GroupInfo myGroup = activeGroups.get(groupName);
        	
        	String nodeName = null;
        	byte[] senderId = null;
            int signKeyCurve = 0;

        	// Assign a Sender ID to the joining node, unless it is a monitor
        	if (roleSet != (1 << Constants.GROUP_OSCORE_MONITOR)) {
            	// For the sake of testing, a particular Sender ID is used as known to be available.
                senderId = new byte[] { (byte) 0x25 };
                
            	myGroup.allocateSenderId(senderId);
        	}

        	nodeName = myGroup.allocateNodeName(senderId);
        	
        	if (nodeName == null) {
        		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when assigning a node name");
        		return;
        	}

        	// Retrieve 'client_cred'
        	CBORObject clientCred = joinRequest.get(CBORObject.FromObject(Constants.CLIENT_CRED));
        	
        	if (clientCred == null && (roleSet != (1 << Constants.GROUP_OSCORE_MONITOR))) {
        		
        		// TODO: check if the Group Manager already owns this client's public key
        		
        	}
        	if (clientCred == null && (roleSet != (1 << Constants.GROUP_OSCORE_MONITOR))) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "A public key was neither provided nor found as already stored");
        		return;
        	}
        	
        	// Process the public key of the joining node
        	else if (roleSet != (1 << Constants.GROUP_OSCORE_MONITOR)) {
        		
        		OneKey publicKey = null;
        		boolean valid = false;
        		
        		switch(myGroup.getPubKeyEnc()) {
	        		case Constants.COSE_HEADER_PARAM_CWT:
	        	        if (clientCred.getType() == CBORType.Map) {
	        	        	publicKey = Util.uccsToOneKey(clientCred);
	        	        	valid = true;
	        	        }
	        	        else if (clientCred.getType() == CBORType.Array) {
	        	            // Retrieve the public key from the CWT
	        	            // TODO
	        	        }
	        	        else {
	        	            Assert.fail("Invalid format of public key");
	        	        }
	        	        break;
	        	    case Constants.COSE_HEADER_PARAM_X5CHAIN:
	        	        // Retrieve the public key from the certificate
	        	        if (clientCred.getType() == CBORType.ByteString) {
	        	            // TODO
	        	        }
	        	        else {
	        	            Assert.fail("Invalid format of public key");
	        	        }
	        	        break;
	        	    default:
	        	        Assert.fail("Invalid format of public key");
        		}
        		if (publicKey == null ||  valid == false) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
        		}
        		
        		        		
        		// Sanity check on the type of public key        		
        		if (myGroup.getSignAlg().equals(AlgorithmID.ECDSA_256) ||
        		    myGroup.getSignAlg().equals(AlgorithmID.ECDSA_384) ||
        		    myGroup.getSignAlg().equals(AlgorithmID.ECDSA_512)) {
        			
        			// Invalid public key format
        			if (!publicKey.get(KeyKeys.KeyType).equals(myGroup.getSignParams().get(0).get(0)) || // alg capability: key type
                   		!publicKey.get(KeyKeys.KeyType).equals(myGroup.getSignParams().get(1).get(0)) || // key capability: key type
                   		!publicKey.get(KeyKeys.EC2_Curve).equals(myGroup.getSignParams().get(1).get(1))) // key capability: curve
        			{ 
        					
	            			myGroup.deallocateSenderId(senderId);

                    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                			return;
                        		
                	}

        		}
        		
        		if (myGroup.getSignAlg().equals(AlgorithmID.EDDSA)) {
        			
        			// Invalid public key format
        			if (!publicKey.get(KeyKeys.KeyType).equals(myGroup.getSignParams().get(0).get(0)) || // alg capability: key type
               			!publicKey.get(KeyKeys.KeyType).equals(myGroup.getSignParams().get(1).get(0)) || // key capability: key type
               			!publicKey.get(KeyKeys.OKP_Curve).equals(myGroup.getSignParams().get(1).get(1))) // key capability: curve
        			{
		            			
    						myGroup.deallocateSenderId(senderId);

                    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                			return;
                    		
            		}
        				
        		}
        		
        		// Retrieve the proof-of-possession nonce and evidence from the Client
        		CBORObject cnonce = joinRequest.get(CBORObject.FromObject(Constants.CNONCE));
            	
        		// A client nonce must be included for proof-of-possession for joining OSCORE groups
            	if (cnonce == null) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
            	}

            	// The client nonce must be wrapped in a binary string for joining OSCORE groups
            	if (!cnonce.getType().equals(CBORType.ByteString)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
                }
            	        		
        		// Check the proof-of-possession evidence over (scope | rsnonce | cnonce), using the Client's public key
            	CBORObject clientPopEvidence = joinRequest.get(CBORObject.FromObject(Constants.CLIENT_CRED_VERIFY));
            	
            	// A client PoP evidence must be included
            	if (clientPopEvidence == null) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
            	}

            	// The client PoP evidence must be wrapped in a binary string
            	if (!clientPopEvidence.getType().equals(CBORType.ByteString)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
                }
            	
            	byte[] rawClientPopEvidence = clientPopEvidence.GetByteString();
        		
            	PublicKey pubKey = null;
                try {
					pubKey = publicKey.AsPublicKey();
				} catch (CoseException e) {
					System.out.println(e.getMessage());
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP evidence");
            		return;
				}
                if (pubKey == null) {
                	exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP evidence");
            		return;
                }

                int offset = 0;
                
                byte[] serializedScopeCBOR = CBORObject.FromObject(scope).EncodeToBytes();
                byte[] serializedGMNonceCBOR = CBORObject.FromObject(rsnonce).EncodeToBytes();
                byte[] serializedCNonceCBOR = cnonce.EncodeToBytes();
                byte[] popInput = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
                System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
                offset += serializedScopeCBOR.length;
                System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
                offset += serializedGMNonceCBOR.length;
                System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);


                // The group mode is used. The PoP evidence is a signature
                if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
                    
                    if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_EC2))
                        signKeyCurve = publicKey.get(KeyKeys.EC2_Curve).AsInt32();
                    else if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_OKP))
                        signKeyCurve = publicKey.get(KeyKeys.OKP_Curve).AsInt32();

                    // This should never happen, due to the previous sanity checks
                    if (signKeyCurve == 0) {
                        exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when setting up the signature verification");
                        return;
                    }

                    // Invalid Client's PoP signature
                    if (!Util.verifySignature(signKeyCurve, pubKey, popInput, rawClientPopEvidence)) {
                    	byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                    	exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                        return;
                    }
                }
                // Only the pairwise mode is used. The PoP evidence is a MAC
                else {
                    // TODO
                }
        		        		
                if (!myGroup.storePublicKey(senderId, clientCred)) {
        			myGroup.deallocateSenderId(senderId);
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when storing the public key");
            		return;
        			
        		}
        		
        	}
        	
        	if (myGroup.isGroupMember(subject) == true) {
        		// This node is re-joining the group without having left
        		
            	String oldNodeName = myGroup.getGroupMemberName(subject);
            	
            	Resource staleResource = getChild("nodes").getChild(oldNodeName);
        		this.getChild("nodes").getChild(oldNodeName).delete(staleResource);
        		
        		myGroup.removeGroupMemberBySubject(subject);
        		
        	}
        	
        	if (!myGroup.addGroupMember(senderId, nodeName, roleSet, subject)) {
        		// The joining node is not a monitor; its node name is its Sender ID encoded as a String
    			if (senderId != null) {
    				myGroup.deallocateSenderId(senderId);    				
    			}
    			// The joining node is a monitor; it got a node name but not a Sender ID
    			else {
    				myGroup.deallocateNodeName(nodeName);
    			}
    			myGroup.deleteBirthGid(nodeName);
    			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when adding the new group member");
        		return;
        	}
        	
        	// Create and add the sub-resource associated to the new group member
        	try {
        		valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName));
        		valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName + "/pub-key"));
    		}
    		catch(AceException e) {
    			myGroup.removeGroupMemberBySubject(subject);
    			
    			// The joining node is not a monitor
    			if (senderId != null) {
	    			myGroup.deallocateSenderId(senderId);
	    			myGroup.deletePublicKey(senderId);
    			}
    			
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when creating the node sub-resource");
        		return;
    		}

        	Set<Short> actions = new HashSet<>();
        	actions.add(Constants.GET);
        	actions.add(Constants.PUT);
        	actions.add(Constants.DELETE);
        	myScopes.get(rootGroupMembershipResource + "/" + groupName)
        	        .put(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName, actions);
        	Resource nodeCoAPResource = new GroupOSCORESubResourceNodename(nodeName);
        	this.getChild("nodes").add(nodeCoAPResource);
        	
        	actions = new HashSet<>();
        	actions.add(Constants.POST);
        	myScopes.get(rootGroupMembershipResource + "/" + groupName)
	                .put(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName + "/pub-key", actions);
        	nodeCoAPResource = new GroupOSCORESubResourceNodenamePubKey("pub-key");
        	this.getChild("nodes").getChild(nodeName).add(nodeCoAPResource);
        	
        	
            // Respond to the Join Request
            
        	CBORObject joinResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	joinResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	// Fill the 'key' parameter
        	if (senderId != null) {
    			// The joining node is not a monitor
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.group_SenderID, senderId);
        	}
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.pub_key_enc, targetedGroup.getPubKeyEnc());
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
        	    // The group mode is used
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg, targetedGroup.getSignEncAlg().AsCBOR());
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
        	    if (targetedGroup.getSignParams().size() != 0)
        	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
        	}
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
        	    // The pairwise mode is used
        	    myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
        	    if (targetedGroup.getEcdhParams().size() != 0)
        	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
        	}
        	joinResponse.Add(Constants.KEY, myMap);
        	
        	// If backward security has to be preserved:
        	//
        	// 1) The Epoch part of the Group ID should be incremented
        	// myGroup.incrementGroupIdEpoch();
        	//
        	// 2) The OSCORE group should be rekeyed

        	// The current version of the symmetric keying material
        	joinResponse.Add(Constants.NUM, CBORObject.FromObject(myGroup.getVersion()));
        	
        	// CBOR Value assigned to the coap_group_oscore profile.
        	joinResponse.Add(Constants.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(Constants.COAP_GROUP_OSCORE_APP));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	joinResponse.Add(Constants.EXP, CBORObject.FromObject(1000000));

        	if (providePublicKeys) {

        		CBORObject pubKeysArray = CBORObject.NewArray();        		
        		CBORObject peerRoles = CBORObject.NewArray();
        		CBORObject peerIdentifiers = CBORObject.NewArray();
        		
        		Map<CBORObject, CBORObject> publicKeys = myGroup.getPublicKeys();
            	
        		for (CBORObject sid : publicKeys.keySet()) {
        			// This should never happen; silently ignore
        			if (publicKeys.get(sid) == null)
        				continue;

        			byte[] peerSenderId = sid.GetByteString();
        			// Skip the public key of the just-added joining node
        			if ((senderId != null) && Arrays.equals(senderId, peerSenderId))
        				continue;
        			
        			boolean includePublicKey = false;
                	
        			// Public keys of all group members are requested
        			if (getPubKeys.equals(CBORObject.Null)) {
        				includePublicKey = true;
        			}
        			// Only public keys of group members with certain roles are requested
        			else {
        				for (int i = 0; i < getPubKeys.get(1).size(); i++) {
        					int filterRoles = getPubKeys.get(1).get(i).AsInt32();
        					int memberRoles = myGroup.getGroupMemberRoles(peerSenderId);
        					// The owner of this public key does not have all its roles indicated in this AIF integer filter
        					if (filterRoles != (filterRoles & memberRoles)) {
        						continue;
        					}
        					else {
        						includePublicKey = true;
        						break;
        					}
        				}
        			}
        			
        			if (includePublicKey) {
        				pubKeysArray.Add(publicKeys.get(sid));
	        			peerRoles.Add(myGroup.getGroupMemberRoles(peerSenderId));
	        			peerIdentifiers.Add(peerSenderId);
        			}

        		}
        		    			
        		joinResponse.Add(Constants.PUB_KEYS, pubKeysArray);
    			joinResponse.Add(Constants.PEER_ROLES, peerRoles);
    			joinResponse.Add(Constants.PEER_IDENTIFIERS, peerIdentifiers);
        			
        		
        		// Debug:
        		// 1) Print 'kid' as equal to the Sender ID of the key owner
        		// 2) Print 'kty' of each public key
        		/*
        		for (int i = 0; i < coseKeySet.size(); i++) {
        			byte[] kid = coseKeySet.get(i).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        			for (int j = 0; j < kid.length; j++)
        				System.out.printf("0x%02X", kid[j]);
        			System.out.println("\n" + coseKeySet.get(i).get(KeyKeys.KeyType.AsCBOR()));
        		}
        		*/
        		
        	}
        	
        	// Group Policies
        	joinResponse.Add(Constants.GROUP_POLICIES, myGroup.getGroupPolicies());
        	
        	
        	// Public key of the Group Manager together with proof-of-possession evidence
        	byte[] kdcNonce = new byte[8];
        	new SecureRandom().nextBytes(kdcNonce);
        	joinResponse.Add(Constants.KDC_NONCE, kdcNonce);
        	
        	CBORObject publicKey = targetedGroup.getGmPublicKey();
        	
        	joinResponse.Add(Constants.KDC_CRED, publicKey);
        	
        	PrivateKey gmPrivKey;
			try {
				gmPrivKey = targetedGroup.getGmKeyPair().AsPrivateKey();
			} catch (CoseException e) {
				System.err.println("Error when computing the GM PoP evidence " + e.getMessage());
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when computing the GM PoP evidence");
        		return;
			}
        	byte[] gmSignature = Util.computeSignature(signKeyCurve,gmPrivKey, kdcNonce);

        	if (gmSignature != null) {
        	    joinResponse.Add(Constants.KDC_CRED_VERIFY, gmSignature);
        	}
        	else {
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when computing the GM PoP evidence");
        		return;
        	}
        	
        	byte[] responsePayload = joinResponse.EncodeToBytes();
        	String uriNodeResource = new String(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        	
        	Response coapJoinResponse = new Response(CoAP.ResponseCode.CREATED);
        	coapJoinResponse.setPayload(responsePayload);
        	coapJoinResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        	coapJoinResponse.getOptions().setLocationPath(uriNodeResource);

        	exchange.respond(coapJoinResponse);
        	
        }
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /pub-key
     */
    public static class GroupOSCORESubResourcePubKey extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourcePubKey(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"pub-key\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		
        		// The requester is not a current group member.
        		//
        		// This is still fine, as long as at least one Access Tokens
        		// of the requester allows also the role "Verifier" in this group
        		
        		// Check that at least one of the Access Tokens for this node allows (also) the Verifier role for this group
            	
        		int role = 1 << Constants.GROUP_OSCORE_VERIFIER;
        		boolean allowed = false;
            	int[] roleSetToken = getRolesFromToken(subject, groupName);
            	if (roleSetToken == null) {
            		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
            		return;
            	}
            	else {
            		for (int index = 0; index < roleSetToken.length; index++) {
            			if ((role & roleSetToken[index]) != 0) {
                			// 'scope' in this Access Token admits (also) the role "Verifier" for this group. This makes it fine for the requester.
            				allowed = true;
            				break;
            			}
            		}
            	}
            	
            	if (!allowed) {
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation not permitted to a non-member which is not a Verifier");
            		return;
            	}
            	
        	}
            
        	// Respond to the Public Key Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	CBORObject pubKeysArray = CBORObject.NewArray();        	
    		CBORObject peerRoles = CBORObject.NewArray();
    		CBORObject peerIdentifiers = CBORObject.NewArray();
    		
    		Map<CBORObject, CBORObject> publicKeys = targetedGroup.getPublicKeys();
    		
    		for (CBORObject sid : publicKeys.keySet()) {
    			
    			// This should never happen; silently ignore
    			if (publicKeys.get(sid) == null)
    				continue;
    			
    			byte[] peerSenderId = sid.GetByteString();
    			// This should never happen; silently ignore
    			if (peerSenderId == null)
    				continue;
    			
    			pubKeysArray.Add(publicKeys.get(sid));
    			peerRoles.Add(targetedGroup.getGroupMemberRoles(peerSenderId));
    			peerIdentifiers.Add(peerSenderId);
    			
    		}
    		
    		myResponse.Add(Constants.NUM, CBORObject.FromObject(targetedGroup.getVersion()));

    		myResponse.Add(Constants.PUB_KEYS, pubKeysArray);			
			myResponse.Add(Constants.PEER_ROLES, peerRoles);
			myResponse.Add(Constants.PEER_IDENTIFIERS, peerIdentifiers);

        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
        @Override
        public void handleFETCH(CoapExchange exchange) {
        	System.out.println("FETCH request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		
        		// The requester is not a current group member.
        		//
        		// This is still fine, as long as at least one Access Tokens
        		// of the requester allows also the role "Verifier" in this group
        		
        		// Check that at least one of the Access Tokens for this node allows (also) the Verifier role for this group
            	
        		int role = 1 << Constants.GROUP_OSCORE_VERIFIER;
        		boolean allowed = false;
            	int[] roleSetToken = getRolesFromToken(subject, groupName);
            	if (roleSetToken == null) {
            		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
            		return;
            	}
            	else {
            		for (int index = 0; index < roleSetToken.length; index++) {
            			if ((role & roleSetToken[index]) != 0) {
                			// 'scope' in this Access Token admits (also) the role "Verifier" for this group. This makes it fine for the requester.
            				allowed = true;
            				break;
            			}
            		}
            	}
            	
            	if (!allowed) {
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation not permitted to a non-member which is not a Verifier");
            		return;
            	}
            	
        	}
        	        	
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	if(requestPayload == null) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "A payload must be present");
        		return;
        	}
        	
        	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
			
        	boolean valid = true;
		    
        	// The payload of the request must be a CBOR Map
        	if (!requestCBOR.getType().equals(CBORType.Map)) {
        		valid = false;
        		
        	}

        	// The CBOR Map must include exactly one element, i.e. 'get_pub_keys'
        	if ((requestCBOR.size() != 1) || (!requestCBOR.ContainsKey(Constants.GET_PUB_KEYS))) {
        		valid = false;
        		
        	}

        	// Invalid format of 'get_pub_keys'
    		if (!valid) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_pub_keys'");
	    		return;
    		}
    		
        	// Retrieve 'get_pub_keys'
        	// This parameter must be a CBOR array or the CBOR simple value Null
        	CBORObject getPubKeys = requestCBOR.get(CBORObject.FromObject((Constants.GET_PUB_KEYS)));
        	
    	    // Invalid format of 'get_pub_keys'
    	    if (!getPubKeys.getType().equals(CBORType.Array) && !getPubKeys.equals(CBORObject.Null)) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_pub_keys'");
	    		return;
    	    }
    			    
    	    if (getPubKeys.getType().equals(CBORType.Array)) {
    	    
	    		// 'get_pub_keys' must include exactly two elements, both of which CBOR arrays
	    		if ( getPubKeys.size() != 3 ||
	    			!getPubKeys.get(0).getType().equals(CBORType.Boolean) ||
	    			!getPubKeys.get(1).getType().equals(CBORType.Array) ||
	    			!getPubKeys.get(2).getType().equals(CBORType.Array)) {
	    			
	    			valid = false;
	        		
	    		}
	
	    		// Invalid format of 'get_pub_keys'
	    		if (valid && getPubKeys.get(1).size() == 0 && getPubKeys.get(2).size() == 0) {
	    			valid = false;
	    		}
	    		
	    		// Invalid format of 'get_pub_keys'
	    		if (getPubKeys.get(0).AsBoolean() == false && getPubKeys.get(2).size() == 0) {
	    			valid = false;
	    		}
	    		
	    		// Invalid format of 'get_pub_keys'
	    		if (valid) {
					for (int i = 0; i < getPubKeys.get(1).size(); i++) {
						// Possible elements of the first array have to be all integers and
						// express a valid combination of roles encoded in the AIF data model
						if (!getPubKeys.get(1).get(i).getType().equals(CBORType.Integer) ||
							!validRoleCombinations.contains(getPubKeys.get(1).get(i).AsInt32())) {
								valid = false;
								break;
								
						}
					}
	    		}
	    		
	    		// Invalid format of 'get_pub_keys'
	    		if (valid) {
					for (int i = 0; i < getPubKeys.get(2).size(); i++) {
						// Possible elements of the second array have to be all
						// byte strings, specifying Sender IDs of other group members
						if (!getPubKeys.get(2).get(i).getType().equals(CBORType.ByteString)) {
							valid = false;
							break;
							
						}			
					}
	    		}
				
	    		// Invalid format of 'get_pub_keys'
	    		if (!valid) {
					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_pub_keys'");
		    		return;
	    		}
    		
    	    }
    		
    		
        	// Respond to the Public Key Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	CBORObject pubKeysArray = CBORObject.NewArray();
    		CBORObject peerRoles = CBORObject.NewArray();
    		CBORObject peerIdentifiers = CBORObject.NewArray();
    		Set<Integer> requestedRoles = new HashSet<Integer>();
    		Set<ByteBuffer> requestedSenderIDs = new HashSet<ByteBuffer>();
    		
    		Map<CBORObject, CBORObject> publicKeys = targetedGroup.getPublicKeys();
    		
    		// Provide the public keys of all the group members
    		if (getPubKeys.equals(CBORObject.Null)) {
    			
    			for (CBORObject sid : publicKeys.keySet()) {
    				
	    			// This should never happen; silently ignore
	    			if (publicKeys.get(sid) == null)
	    				continue;
	    			
	    			byte[] memberSenderId = sid.GetByteString();
	    			// This should never happen; silently ignore
	    			if (memberSenderId == null)
	    				continue;
	
	    			int memberRoles = targetedGroup.getGroupMemberRoles(memberSenderId);
	    			
	    			pubKeysArray.Add(publicKeys.get(sid));
	    			peerRoles.Add(memberRoles);
	    			peerIdentifiers.Add(memberSenderId);
	    			
    			}
    			
    		}
    		// Provide the public keys based on the specified filtering
    		else {
    		
	    		// Retrieve the inclusion flag
				boolean inclusionFlag = getPubKeys.get(0).getType().equals(CBORType.Boolean);
	    		
	    		// Retrieve and store the combination of roles specified in the request
	    		for (int i = 0; i < getPubKeys.get(1).size(); i++) {
	    			requestedRoles.add((getPubKeys.get(1).get(i).AsInt32()));
	    		}
	    		
	    		// Retrieve and store the Sender IDs specified in the request
	    		for (int i = 0; i < getPubKeys.get(2).size(); i++) {
	    			byte[] myArray = getPubKeys.get(2).get(i).GetByteString();
	    			ByteBuffer myBuffer = ByteBuffer.wrap(myArray);
	    			requestedSenderIDs.add(myBuffer);
	    		}
    		
	    		for (CBORObject sid : publicKeys.keySet()) {
	    			
	    			// This should never happen; silently ignore
	    			if (publicKeys.get(sid) == null)
	    				continue;
	    			
	    			byte[] memberSenderId = sid.GetByteString();
	    			// This should never happen; silently ignore
	    			if (memberSenderId == null)
	    				continue;
	
	    			int memberRoles = targetedGroup.getGroupMemberRoles(memberSenderId);
	    			
	    			boolean include = false;
	    			
					for (Integer filter : requestedRoles) {
						int filterRoles = filter.intValue();
						
						// The role(s) of the key owner match with the role filter
						if (filterRoles == (filterRoles & memberRoles)) {
							
							// This public key has to be included anyway,
							// regardless the Sender ID of the key owner
							if (inclusionFlag) {
								include = true;
							}
							// This public key has to be included only if the Sender ID
							// of the key owner is not in the node identifier filter
							else if (!requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
								include = true;
							}
							// Stop going through the role filter anyway;
							// this public key has not to be included
							break;
						}	
					}
	    			
	    			if(!include) {
	    				// This public has to be included if the Sender ID of the key owner is in the node identifier filter
	    				if (inclusionFlag && requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
	    					include = true;
	    				}
	    				// This public has to be included if the Sender ID of the key owner is not in the node identifier filter
	    				else if (!inclusionFlag && !requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
	    					include = true;
	    				}
	    			}
	    			
	    			if (include) {
	    				
	    				pubKeysArray.Add(publicKeys.get(sid));
		    			peerRoles.Add(memberRoles);
		    			peerIdentifiers.Add(memberSenderId);
		    			
	    			}
	    			
	    		}
    		}
    		
    		myResponse.Add(Constants.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
    		
    		myResponse.Add(Constants.PUB_KEYS, pubKeysArray);
			myResponse.Add(Constants.PEER_ROLES, peerRoles);
			myResponse.Add(Constants.PEER_IDENTIFIERS, peerIdentifiers);
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
    }

    /**
     * Definition of the Group OSCORE group-membership sub-resource /gm-pub-key
     */
    public static class GroupOSCORESubResourceGmPubKey extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceGmPubKey(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"gm-pub-key\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		
        		// The requester is not a current group member.
        		//
        		// This is still fine, as long as at least one Access Tokens
        		// of the requester allows also the role "Verifier" in this group
        		
        		// Check that at least one of the Access Tokens for this node allows (also) the Verifier role for this group
            	
        		int role = 1 << Constants.GROUP_OSCORE_VERIFIER;
        		boolean allowed = false;
            	int[] roleSetToken = getRolesFromToken(subject, groupName);
            	if (roleSetToken == null) {
            		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
            		return;
            	}
            	else {
            		for (int index = 0; index < roleSetToken.length; index++) {
            			if ((role & roleSetToken[index]) != 0) {
                			// 'scope' in this Access Token admits (also) the role "Verifier" for this group. This makes it fine for the requester.
            				allowed = true;
            				break;
            			}
            		}
            	}
            	
            	if (!allowed) {
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation not permitted to a non-member which is not a Verifier");
            		return;
            	}
            	
        	}
            
        	// Respond to the Group Manager Public Key Request
            
        	CBORObject myResponse = CBORObject.NewMap();
    		
    		// Public key of the Group Manager together with proof-of-possession evidence
        	byte[] kdcNonce = new byte[8];
        	new SecureRandom().nextBytes(kdcNonce);
        	myResponse.Add(Constants.KDC_NONCE, kdcNonce);
        	
        	CBORObject publicKey = targetedGroup.getGmPublicKey();
        	
        	myResponse.Add(Constants.KDC_CRED, publicKey);
        	
        	PrivateKey gmPrivKey;
			try {
				gmPrivKey = targetedGroup.getGmKeyPair().AsPrivateKey();
			} catch (CoseException e) {
				System.err.println("Error when computing the GM PoP evidence " + e.getMessage());
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when computing the GM PoP evidence");
        		return;
			}
			int signKeyCurve = 0;
			if (targetedGroup.getGmKeyPair().get(KeyKeys.KeyType).AsInt32() == KeyKeys.KeyType_EC2.AsInt32()) {
				signKeyCurve = targetedGroup.getGmKeyPair().get(KeyKeys.EC2_Curve).AsInt32();
			}
			if (targetedGroup.getGmKeyPair().get(KeyKeys.KeyType).AsInt32() == KeyKeys.KeyType_OKP.AsInt32()) {
				signKeyCurve = targetedGroup.getGmKeyPair().get(KeyKeys.OKP_Curve).AsInt32();
			}
			
        	byte[] gmSignature = Util.computeSignature(signKeyCurve, gmPrivKey, kdcNonce);

        	if (gmSignature != null) {
        		myResponse.Add(Constants.KDC_CRED_VERIFY, gmSignature);
        	}
        	else {
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when computing the GM PoP evidence");
        		return;
        	}

        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
    
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /verif-data
     */
    public static class GroupOSCORESubResourceVerifData extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceVerifData(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"verif-data\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
            boolean allowed = false;
        	if (!targetedGroup.isGroupMember(subject)) {
        		
        		// The requester is not a current group member.
        		
        		// Check that at least one of the Access Tokens for this node allows (also) the Verifier role for this group
            	
        		int role = 1 << Constants.GROUP_OSCORE_VERIFIER;
            	int[] roleSetToken = getRolesFromToken(subject, groupName);
            	if (roleSetToken == null) {
            		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when retrieving allowed roles from Access Tokens");
            		return;
            	}
            	else {
            		for (int index = 0; index < roleSetToken.length; index++) {
            			if ((role & roleSetToken[index]) != 0) {
                			// 'scope' in this Access Token admits (also) the role "Verifier" for this group. This makes it fine for the requester.
            				allowed = true;
            				break;
            			}
            		}
            	}
            	
        	}
        	if (!allowed) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation permitted only to a non-member acting as a Verifier");
        		return;
        	}
        	
        	// Respond to the Public Key Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	myResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	// Fill the 'key' parameter
        	// Note that no Sender ID is included
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.pub_key_enc, targetedGroup.getPubKeyEnc());
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
        		// The group mode is used
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg, targetedGroup.getSignEncAlg().AsCBOR());
            	myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
            	if (targetedGroup.getSignParams().size() != 0)
            		myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
        	}
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
        		// The pairwise mode is used
        		myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
            	myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
            	if (targetedGroup.getEcdhParams().size() != 0)
            		myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
        	}
        	
        	myResponse.Add(Constants.KEY, myMap);
        	
    		myResponse.Add(Constants.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
    		
    		// CBOR Value assigned to the coap_group_oscore profile.
        	myResponse.Add(Constants.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(Constants.COAP_GROUP_OSCORE_APP));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	myResponse.Add(Constants.EXP, CBORObject.FromObject(1000000));

        	myResponse.Add(Constants.GROUP_KEY_ENC, targetedGroup.getGroupEncryptionKey());
        	

        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
    
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /num
     */
    public static class GroupOSCORESubResourceNum extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceNum(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"num\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {	
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
            	
        	// Respond to the Version Request
            
        	CBORObject myResponse = CBORObject.FromObject(targetedGroup.getVersion());
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /active
     */
    public static class GroupOSCORESubResourceActive extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceActive(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"active\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {	
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
            	
        	// Respond to the Version Request
            
        	CBORObject myResponse = CBORObject.FromObject(targetedGroup.getStatus());
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /policies
     */
    public static class GroupOSCORESubResourcePolicies extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourcePolicies(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"policies\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {	
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
            	
        	// Respond to the Policies Request
            
        	CBORObject myResponse = null;
        	CBORObject groupPolicies = targetedGroup.getGroupPolicies();
        	
        	if (groupPolicies == null) {
            	// This should not happen for this Group Manager, since default policies apply if not specified when creating the group
        		myResponse = CBORObject.FromObject(new byte[0]);
        	}
        	else {
        		myResponse = CBORObject.NewMap();
        		myResponse.Add(Constants.GROUP_POLICIES, groupPolicies);
        	}
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /nodes
     * 
     * This resource has no handlers and is not directly accessed.
     * It acts as root resource to actual sub-resources for each group member.
     * 
     */
    public static class GroupOSCORESubResourceNodes extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceNodes(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"nodes\" " + resId);
            
        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /nodes/NODENAME
     * for the group members with node name "NODENAME"
     */
    public static class GroupOSCORESubResourceNodename extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceNodename(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"nodes/NODENAME\" " + resId);
            
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
        	
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
        		
        	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
        		// The requester is not the group member associated to this sub-resource.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members associated to this sub-resource");
        		return;
        	}
            	
        	// Respond to the Key Distribution Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	myResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
            byte[] senderId = null;
    		String myString = targetedGroup.getGroupMemberName(subject);
            
        	if (targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject))) != (1 << Constants.GROUP_OSCORE_MONITOR)) {
        		// The requester is not a monitor, hence it has a Sender ID
        		senderId = Utils.hexToBytes(myString.substring(myString.indexOf(nodeNameSeparator) + 1));
        	}
        	
        	// Fill the 'key' parameter
        	if (senderId != null) {
        		// The joining node is not a monitor
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.group_SenderID, senderId);
        	}
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.pub_key_enc, targetedGroup.getPubKeyEnc());
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
        	    // The group mode is used
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg, targetedGroup.getSignEncAlg().AsCBOR());
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
        	    if (targetedGroup.getSignParams().size() != 0)
        	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
        	}
        	if (targetedGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
        	    // The pairwise mode is used
        	    myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
        	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
        	    if (targetedGroup.getEcdhParams().size() != 0)
        	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
        	}
        	myResponse.Add(Constants.KEY, myMap);
        	
        	// The current version of the symmetric keying material
        	myResponse.Add(Constants.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
        	
        	// CBOR Value assigned to the coap_group_oscore profile.
        	myResponse.Add(Constants.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(Constants.COAP_GROUP_OSCORE_APP));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	myResponse.Add(Constants.EXP, CBORObject.FromObject(1000000));
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);
        	
        }
        
        @Override
        public void handlePUT(CoapExchange exchange) {
        	System.out.println("PUT request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
        	if (request.getPayloadSize() != 0) {
        		// This request must not have a payload
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "This request must not have a payload");
        		return;
        	}
        	
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
        	
        	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
        		// The requester is not the group member associated to this sub-resource.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members associated to this sub-resource");
        		return;
        	}
        	
        	if (targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject))) == (1 << Constants.GROUP_OSCORE_MONITOR)) {
        		// The requester is a monitor, hence it is not supposed to have a Sender ID.
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation not permitted to members that are only monitors");
        		return;
        	}
        	
        	
        	// Here the Group Manager simply assigns a new Sender ID to this group member.
        	// More generally, the Group Manager may alternatively or additionally rekey the whole OSCORE group 
        	// Note that the node name does not change.
        	
        	byte[] oldSenderId = targetedGroup.getGroupMemberSenderId(subject).GetByteString();
        	
        	byte[] senderId = targetedGroup.allocateSenderId();
        	
        	if (senderId == null) {
        		// All possible values are already in use for this OSCORE group
        		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "No available Sender IDs in this OSCORE group");
        		return;
        	}
        	
        	int roles = targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject)));
        	targetedGroup.setGroupMemberRoles(senderId, roles);
        	targetedGroup.setSenderIdToIdentity(subject, senderId);
        	
        	CBORObject publicKey = targetedGroup.getPublicKey(oldSenderId);
        	
        	// Store this client's public key under the new Sender ID
        	if (!targetedGroup.storePublicKey(senderId, publicKey)) {
        	    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when storing the public key");
        	    return;
        	}
        	// Delete this client's public key under the old Sender ID
        	targetedGroup.deletePublicKey(oldSenderId);
        	
        	
        	// Respond to the Key Renewal Request
        	
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	// The new Sender ID assigned to the group member
        	myResponse.Add(Constants.GROUP_SENDER_ID, CBORObject.FromObject(senderId));
        	        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);
        	
        }
        
        
        @Override
        public void handleDELETE(CoapExchange exchange) {
        	System.out.println("DELETE request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
        	
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
            
        	if (!targetedGroup.isGroupMember(subject)) {
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
        	
        	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
        		// The requester is not the group member associated to this sub-resource.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members associated to this sub-resource");
        		return;
        	}
        	
        	targetedGroup.removeGroupMemberBySubject(subject);
        	
        	// Respond to the Group Leaving Request
            
        	Response coapResponse = new Response(CoAP.ResponseCode.DELETED);

        	delete();
        	exchange.respond(coapResponse);
        	
        }
        
    }
    
    /**
     * Definition of the Group OSCORE group-membership sub-resource /nodes/NODENAME/pub-key
     * for the group members with node name "NODENAME"
     */
    public static class GroupOSCORESubResourceNodenamePubKey extends CoapResource {
    	
		/**
         * Constructor
         * @param resId  the resource identifier
         */
        public GroupOSCORESubResourceNodenamePubKey(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"nodes/NODENAME/pub-key\" " + resId);
            
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
        	System.out.println("POST request reached the GM");
        	
        	// Retrieve the entry for the target group, using the last path segment of the URI path as the name of the OSCORE group
        	GroupInfo targetedGroup = activeGroups.get(this.getParent().getParent().getParent().getName());
        	
        	// This should never happen if active groups are maintained properly
        	if (targetedGroup == null) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
            	return;
        	}
        	
        	String groupName = targetedGroup.getGroupName();
        	
        	// This should never happen if active groups are maintained properly
  	  		if (!groupName.equals(this.getParent().getParent().getParent().getName())) {
            	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, "Error when retrieving material for the OSCORE group");
  				return;
  			}
        	
        	String subject = null;
        	Request request = exchange.advanced().getCurrentRequest();
            
            try {
				subject = CoapReq.getInstance(request).getSenderId();
			} catch (AceException e) {
			    System.err.println("Error while retrieving the client identity: " + e.getMessage());
			}
            if (subject == null) {
            	// At this point, this should not really happen, due to the earlier check at the Token Repository
            	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Unauthenticated client tried to get access");
            	return;
            }
        	
        	if (!targetedGroup.isGroupMember(subject)) {
        		// The requester is not a current group member.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members");
        		return;
        	}
        	
        	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getParent().getName())) {
        		// The requester is not the group member associated to this sub-resource.
        		exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, "Operation permitted only to group members associated to this sub-resource");
        		return;
        	}
        	
        	if (targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject))) == (1 << Constants.GROUP_OSCORE_MONITOR)) {
        		// The requester is a monitor, hence it is not supposed to have a Sender ID.
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Operation not permitted to members that are only monitors");
        		return;
        	}
        	
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	if(requestPayload == null) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "A payload must be present");
        	    return;
        	}

        	CBORObject PublicKeyUpdateRequest = CBORObject.DecodeFromBytes(requestPayload);

        	// The payload of the Public Key Update Request must be a CBOR Map
        	if (!PublicKeyUpdateRequest.getType().equals(CBORType.Map)) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The payload must be a CBOR map");
        	    return;
        	}
        	
        	if (!PublicKeyUpdateRequest.ContainsKey(Constants.CLIENT_CRED)) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Missing parameter: " + "'client_cred'");
        	    return;
        	}
        	
        	if (!PublicKeyUpdateRequest.ContainsKey(Constants.CNONCE)) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Missing parameter: " + "'cnonce'");
        	    return;
        	}
        	
        	if (!PublicKeyUpdateRequest.ContainsKey(Constants.CLIENT_CRED_VERIFY)) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Missing parameter: " + "'client_cred_verify'");
        	    return;
        	}
        	
        	// Retrieve 'client_cred'
        	CBORObject clientCred = PublicKeyUpdateRequest.get(CBORObject.FromObject(Constants.CLIENT_CRED));
        	
			// client_cred cannot be Null
			if (clientCred == null) {
			    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The parameter 'client_cred' cannot be Null");
			    return;
			}

			OneKey publicKey = null;
			boolean valid = false;
			
			switch(targetedGroup.getPubKeyEnc()) {
			    case Constants.COSE_HEADER_PARAM_CWT:
			        if (clientCred.getType() == CBORType.Map) {
			            publicKey = Util.uccsToOneKey(clientCred);
			            valid = true;
			        }
			        else if (clientCred.getType() == CBORType.Array) {
			            // Retrieve the public key from the CWT
			            // TODO
			        }
			        else {
			            Assert.fail("Invalid format of public key");
			        }
			        break;
			    case Constants.COSE_HEADER_PARAM_X5CHAIN:
			        // Retrieve the public key from the certificate
			        if (clientCred.getType() == CBORType.ByteString) {
			            // TODO
			        }
			        else {
			            Assert.fail("Invalid format of public key");
			        }
			        break;
			    default:
			        Assert.fail("Invalid format of public key");
			}
			if (publicKey == null ||  valid == false) {
        	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid public key format");
			    return;
			}
			
			// Sanity check on the type of public key        		
			if (targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_256) ||
			    targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_384) ||
				targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_512)) {
				
				// Invalid public key format
				if (!publicKey.get(KeyKeys.KeyType).equals(targetedGroup.getSignParams().get(0).get(0)) || // alg capability: key type
				    !publicKey.get(KeyKeys.KeyType).equals(targetedGroup.getSignParams().get(1).get(0)) || // key capability: key type
				    !publicKey.get(KeyKeys.EC2_Curve).equals(targetedGroup.getSignParams().get(1).get(1))) // key capability: curve
				{ 
				        
				    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid public key for the algorithm and parameters used in the OSCORE group");
				    return;
				            
				}
			
			}
			
			if (targetedGroup.getSignAlg().equals(AlgorithmID.EDDSA)) {
			
				// Invalid public key format
				if (!publicKey.get(KeyKeys.KeyType).equals(targetedGroup.getSignParams().get(0).get(0)) || // alg capability: key type
				    !publicKey.get(KeyKeys.KeyType).equals(targetedGroup.getSignParams().get(1).get(0)) || // key capability: key type
				    !publicKey.get(KeyKeys.OKP_Curve).equals(targetedGroup.getSignParams().get(1).get(1))) // key capability: curve
				{
				            
				    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid public key for the algorithm and parameters used in the OSCORE group");
				    return;
				        
				}
			    
			}
        	
			// Retrieve the proof-of-possession nonce from the Client
			CBORObject cnonce = PublicKeyUpdateRequest.get(CBORObject.FromObject(Constants.CNONCE));

			// A client nonce must be included for proof-of-possession
			if (cnonce == null) {
			    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The parameter 'cnonce' cannot be Null");
			    return;
			}

			// The client nonce must be wrapped in a binary string
			if (!cnonce.getType().equals(CBORType.ByteString)) {
			    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The parameter 'cnonce' must be a CBOR byte string");
			    return;
			}

			
			
			// Check the PoP evidence over (scope | rsnonce | cnonce), using the Client's public key
			CBORObject clientPopEvidence = PublicKeyUpdateRequest.get(CBORObject.FromObject(Constants.CLIENT_CRED_VERIFY));

			// A client PoP evidence must be included
			if (clientPopEvidence == null) {
			    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The parameter 'client_cred_verify' cannot be Null");
			    return;
			}

			// The client PoP evidence must be wrapped in a binary string for joining OSCORE groups
			if (!clientPopEvidence.getType().equals(CBORType.ByteString)) {
			    exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The parameter 'client_cred_verify' must be a CBOR byte string");
			    return;
			}

			byte[] rawClientPopEvidence = clientPopEvidence.GetByteString();
        	
			PublicKey pubKey = null;
			try {
			    pubKey = publicKey.AsPublicKey();
			} catch (CoseException e) {
			    System.out.println(e.getMessage());
			    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP evidence");
			    return;
			}
			if (pubKey == null) {
			    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP evidence");
			    return;
			}

			// Rebuild the original 'scope' from the Join Request
	        CBORObject cborArrayScope = CBORObject.NewArray();
	        int myRoles = targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject)));
	        cborArrayScope.Add(groupName);
	        cborArrayScope.Add(myRoles);
	        byte[] scope = cborArrayScope.EncodeToBytes();

			// Retrieve the original 'rsnonce' specified in the Token POST response
			String rsNonceString = TokenRepository.getInstance().getRsnonce(subject);
            if(rsNonceString == null) {
            	// Return an error response, with a new nonce for PoP of the Client's private key
        	    CBORObject responseMap = CBORObject.NewMap();
                byte[] rsnonce = new byte[8];
                new SecureRandom().nextBytes(rsnonce);
                responseMap.Add(Constants.KDCCHALLENGE, rsnonce);
                TokenRepository.getInstance().setRsnonce(subject, Base64.getEncoder().encodeToString(rsnonce));
                byte[] responsePayload = responseMap.EncodeToBytes();
            	exchange.respond(CoAP.ResponseCode.BAD_REQUEST, responsePayload, Constants.APPLICATION_ACE_CBOR);
            	return;
            }
			byte[] rsnonce = Base64.getDecoder().decode(rsNonceString);
			
			int offset = 0;
			
			byte[] serializedScopeCBOR = CBORObject.FromObject(scope).EncodeToBytes();
			byte[] serializedGMNonceCBOR = CBORObject.FromObject(rsnonce).EncodeToBytes();
			byte[] serializedCNonceCBOR = cnonce.EncodeToBytes();
			byte[] popInput = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
			System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
			offset += serializedScopeCBOR.length;
			System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
			offset += serializedGMNonceCBOR.length;
			System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
			
			// The group mode is used. The PoP evidence is a signature
			if (targetedGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
				int signKeyCurve = 0;
	
				if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_EC2))
				    signKeyCurve = publicKey.get(KeyKeys.EC2_Curve).AsInt32();
				else if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_OKP))
				    signKeyCurve = publicKey.get(KeyKeys.OKP_Curve).AsInt32();
	
				// This should never happen, due to the previous sanity checks
				if (signKeyCurve == 0) {
				    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when setting up the signature verification");
				    return;
				}
	
				// Invalid Client's PoP signature
				if (!Util.verifySignature(signKeyCurve, pubKey, popInput, rawClientPopEvidence)) {
					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid PoP MAC");
	        		return;
				}
			}
			// Only the pairwise mode is used. The PoP evidence is a MAC
			else {
				// TODO
			}
			
			
			byte[] senderId = targetedGroup.getGroupMemberSenderId(subject).GetByteString();
			
			if (!targetedGroup.storePublicKey(senderId, clientCred)) {
			    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when storing the public key");
			    return;
			}
			
        	// Respond to the Public Key Update Request     	
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CHANGED);
        	
        	exchange.respond(coapResponse);
        	
        }
        
    }
    
    
    /**
     * @param str  the hex string
     * @return  the byte array
     * 
     * Return the byte array representation of the original string
     */
    public static byte[] hexStringToByteArray(final String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        
    	// Big-endian
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) +
                                   Character.digit(str.charAt(i+1), 16));
            data[i / 2] = (byte) (data[i / 2] & 0xFF);
        }
        
    	// Little-endian
        /*
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(str.charAt(len - 2 - i), 16) << 4) +
                                   Character.digit(str.charAt(len - 1 - i), 16));
            data[i / 2] = (byte) (data[i / 2] & 0xFF);
        }
        */
        
        return data;
        
    }
    
    /**
     * @param byteArray  the byte array
     * @return  the hex string
     * 
     * Return the printable hexadecimal string corresponding to a byte array
     */
    public static String byteArrayToHexString(final byte[] byteArray) {
    	
    	if (byteArray == null) {
    		return new String("");
    	}
    	else {
    		String str = new String("");
	    	for (byte byteToConvert: byteArray) {
	            str += String.format("%02X", byteToConvert);
	        }
	    	return str;
    	}
    	
    }

    private static boolean OSCOREGroupCreation(String groupName, int signKeyCurve) throws CoseException, Exception
    {
    	// Create the OSCORE group
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };

        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

        final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
        final int pubKeyEnc = Constants.COSE_HEADER_PARAM_CWT;
        
        // Relevant when using public keys are encoded as a CWT or an Unprotected CWT Claim Set (UCCS).
        // If true, the UCCS encoding is used, otherwise the CWT encodding is used
        final boolean uccsPreferredToCWT = true;

        int mode = Constants.GROUP_OSCORE_GROUP_MODE_ONLY;

        final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
        AlgorithmID signAlg = null;
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
    	signParams.Add(algCapabilities);
    	signParams.Add(keyCapabilities);     
        
        if (activeGroups.containsKey(groupName)) {
        	
        	System.out.println("The OSCORE group " + groupName + " already exists.");
        	return false;
        	
        }
        
        // Prefix (4 byte) and Epoch (2 bytes) --- All Group IDs have the same prefix size, but can have different Epoch sizes
        // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c 
    	final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
    	byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes
    	
    	// Set the asymmetric key pair and public key of the Group Manager
    	String gmKeyPairStr = "";
    	String gmPublicKeyStr = "";
    	
    	OneKey gmKeyPair = null;
    	OneKey gmPublicKeyOneKey = null;
    	CBORObject gmPublicKey = null;

    	// Store the asymmetric key pair and public key of the Group Manager (ECDSA_256)
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    	    gmKeyPairStr = "pgMmAQIgASFYICI2ZYymdbti17JGI9sEU6O5BTO3w7IhzBwsc8TpGdVAIlggdwkWvEyXw8RmBPQwsGFwx7PWBiYzdWYowxGA+ju2WhsjWCBKe4RKTJfvke0jKqVkydXTc/IJlkf56b0/5kF6DQ+RrQ==";
    	    gmPublicKeyStr = "pQMmAQIgASFYICI2ZYymdbti17JGI9sEU6O5BTO3w7IhzBwsc8TpGdVAIlggdwkWvEyXw8RmBPQwsGFwx7PWBiYzdWYowxGA+ju2Whs=";
    	}
    	    
    	// Store the asymmetric key pair and public key of the Group Manager (EDDSA - Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    	    gmKeyPairStr = "pQMnAQEgBiFYIMbsZl6Be9BkNA58JLuToR6OwHNc5IeQ+cRY9/o0C4yjI1gg0KLOEbK6YUsEiQO3JjjvSjsK9W4aYMb7Zwawwa2KFPs=";
    	    gmPublicKeyStr = "pAMnAQEgBiFYIMbsZl6Be9BkNA58JLuToR6OwHNc5IeQ+cRY9/o0C4yj";
    	}

    	gmKeyPair = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmKeyPairStr)));
    	
    	gmPublicKeyOneKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)));
    	switch (pubKeyEnc) {
        case Constants.COSE_HEADER_PARAM_CWT:
            if (uccsPreferredToCWT == true)
                gmPublicKey = Util.oneKeyToUccs(gmPublicKeyOneKey, "");
            else {
                // Build/retrieve a CWT including the public key
                // TODO
            }
            break;
        case Constants.COSE_HEADER_PARAM_X5CHAIN:
            // Build/retrieve the certificate including the public key
            // TODO
            break;
    	}
    	
    	GroupInfo myGroup = new GroupInfo(groupName,
    									  masterSecret,
    			                          masterSalt,
    			                          groupIdPrefixSize,
    			                          groupIdPrefix,
    			                          groupIdEpoch.length,
    			                          Util.bytesToInt(groupIdEpoch),
    			                          prefixMonitorNames,
    			                          nodeNameSeparator,
    			                          hkdf,
    			                          pubKeyEnc,
    			                          mode,
    			                          signEncAlg,
    			                          signAlg,
    			                          signParams,
    			                          null,
    			                          null,
    			                          null,
    			                          null,
    			                          gmKeyPair,
    			                          gmPublicKey);
        
    	myGroup.setStatus(true);
    	
    	byte[] mySid;
    	String myName;
    	String mySubject;
    	OneKey myKey;
    	
    	
    	
    	// Generate a pair of ECDSA_256 keys and print them in base 64 (whole version, then public only)
    	/*
    	OneKey testKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        
    	byte[] testKeyBytes = testKey.EncodeToBytes();
    	String testKeyBytesBase64 = Base64.getEncoder().encodeToString(testKeyBytes);
    	System.out.println(testKeyBytesBase64);
    	
    	OneKey testPublicKey = testKey.PublicKey();
    	byte[] testPublicKeyBytes = testPublicKey.EncodeToBytes();
    	String testPublicKeyBytesBase64 = Base64.getEncoder().encodeToString(testPublicKeyBytes);
    	System.out.println(testPublicKeyBytesBase64);
    	*/
    	
    	// Add a group member with Sender ID 0x52
    	mySid = new byte[] { (byte) 0x52 };
    	
    	if (!myGroup.allocateSenderId(mySid))
    		return false;
    	myName = myGroup.allocateNodeName(mySid);
    	mySubject = "clientX";
    	
    	int roles = 0;
    	roles = Util.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_REQUESTER);
    	
    	if (!myGroup.addGroupMember(mySid, myName, roles, mySubject))
    		return false;
    	
    	String pkStr1 = "";
    	
    	// Store the public key of the group member with Sender ID 0x52 (ECDSA_256)
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
    		pkStr1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	
    	// Store the public key of the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
    		pkStr1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    	
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(pkStr1)));
    	
    	myGroup.storePublicKey(mySid, Util.oneKeyToUccs(myKey, ""));
    	
    	
    	// Add a group member with Sender ID 0x77
    	mySid = new byte[] { (byte) 0x77 };
    	if (!myGroup.allocateSenderId(mySid))
    		return false;
    	myName = myGroup.allocateNodeName(mySid);
    	mySubject = "clientY";
    	
    	roles = 0;
    	roles = Util.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_REQUESTER);
    	roles = Util.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_RESPONDER);
    	
    	if (!myGroup.addGroupMember(mySid, myName, roles, mySubject))
    		return false;
    	
    	String pkStr2 = "";
    	
    	// Store the public key of the group member with Sender ID 0x77 (ECDSA_256)
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
    		pkStr2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    	
    	// Store the public key of the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
    		pkStr2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    	
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(pkStr2)));
    	
    	myGroup.storePublicKey(mySid, Util.oneKeyToUccs(myKey, ""));
    	
    	// Add this OSCORE group to the set of active groups
    	activeGroups.put(groupName, myGroup);
    	
    	return true;
    	
    }

    /**
     * Return the role sets allowed to a subject in a group, based on all the Access Tokens for that subject
     * 
     * @param subject   Subject identity of the node
     * @param groupName   Group name of the OSCORE group
     * @return The sets of allowed roles for the subject in the specified group using the AIF data model, or null in case of no results
     */
    public static int[] getRolesFromToken(String subject, String groupName) {

    	Set<Integer> roleSets = new HashSet<Integer>();
    	
    	String kid = TokenRepository.getInstance().getKid(subject);
    	Set<String> ctis = TokenRepository.getInstance().getCtis(kid);
    	
    	// This should never happen at this point, since a valid Access Token has just made this request pass through 
    	if (ctis == null)
    		return null;
    	
    	for (String cti : ctis) { //All tokens linked to that pop key
    		
	        //Check if we have the claims for that cti
	        //Get the claims
            Map<Short, CBORObject> claims = TokenRepository.getInstance().getClaims(cti);
            if (claims == null || claims.isEmpty()) {
                //No claims found
        		// Move to the next Access Token for this 'kid'
                continue;
            }
            
	        //Check the scope
            CBORObject scope = claims.get(Constants.SCOPE);
            
        	// This should never happen, since a valid Access Token has just made a request reach a handler at the Group Manager
            if (scope == null) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            if (!scope.getType().equals(CBORType.ByteString)) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		// Move to the next Access Token for this 'kid'
                continue;
            }

        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
            	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
        		
        		if (!scopeEntry.getType().equals(CBORType.Array) || scopeEntry.size() != 2) {
        			// Move to the next Access Token for this 'kid'
                    break;
                }
	        	
	        	// Retrieve the Group ID of the OSCORE group
	        	String scopeStr;
	      	  	CBORObject scopeElement = scopeEntry.get(0);
	      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
	      	  		scopeStr = scopeElement.AsString();
	      	  		if (!scopeStr.equals(groupName)) {
	      	  		    // Move to the next scope entry
	      	  			continue;
	      	  		}
	      	  	}
	      	  	else {
	    			// Move to the next Access Token for this 'kid'
	                break;
	      	  	}
	      	  	
	      	  	// Retrieve the role or list of roles
	      	  	scopeElement = scopeEntry.get(1);
	      	  	
	        	if (!scopeElement.getType().equals(CBORType.Integer)) {
      	  		    // Move to the next scope entry
      	  			continue;
	        	}
	        	
        		int roleSetToken = scopeElement.AsInt32();
        		
        		if (roleSetToken < 0) {
      	  		    // Move to the next scope entry
      	  			continue;
        		}

        		roleSets.add(roleSetToken);
        			        	
        	}
        	
    	}
    	    	
    	// This should never happen, since a valid Access Token has just made a request reach a handler at the Group Manager
    	if (roleSets.size() == 0) {
    		return null;
    	}
    	else {
    		int[] ret = new int[roleSets.size()];
    		
    		int index = 0;
    		for (Integer i : roleSets) {
    			ret[index] = i.intValue();
    			index++;
    		}
    		
    		return ret;
    	}
    	
    }

}
