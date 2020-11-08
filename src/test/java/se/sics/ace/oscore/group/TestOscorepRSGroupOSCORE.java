package se.sics.ace.oscore.group;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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
 * @author Ludwig Seitz, Marco Tiloca & Rikard Hoeglund
 *
 */
public class TestOscorepRSGroupOSCORE {
	
	//Sets the port to use
	private final static int PORT = CoAP.DEFAULT_COAP_PORT;
	
    private final static String rootGroupMembershipResource = "ace-group";
	
	// Up to 4 bytes, same for all the OSCORE Group of the Group Manager
	private final static int groupIdPrefixSize = 4; 
	
	private final static String prefixMonitorNames = "M"; // Initial part of the node name for monitors, since they do not have a Sender ID
	
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
    
    
    // M.T.
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
        // int countersignKeyCurve = KeyKeys.EC2_P256.AsInt32();
        
        // Uncomment to set EDDSA with curve Ed25519 for countersignatures
        int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
 
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
        
        // M.T.
        // Adding the group-membership resource, with group name "feedca570000".
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.POST);
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/pub-key", actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/num", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/active", actions3);
        myResource3.put(rootGroupMembershipResource + "/" + groupName + "/policies", actions3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource3);
        
        // M.T.
        // Adding another group-membership resource, with group name "fBBBca570000".
        // There will NOT be a token enabling the access to this resource.
        Map<String, Set<Short>> myResource4 = new HashMap<>();
        Set<Short> actions4 = new HashSet<>();
        actions4.add(Constants.GET);
        actions4.add(Constants.POST);
        myResource4.put(rootGroupMembershipResource + "/" + "fBBBca570000", actions4);
        myScopes.put(rootGroupMembershipResource + "/" + "fBBBca570000", myResource4);
        
        //Create the OSCORE Group(s)
        if (!OSCOREGroupCreation(groupName, countersignKeyCurve))
        	return;

        // M.T.
        Set<String> auds = new HashSet<>();
        auds.add("rs1"); // Simple test audience
        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResource);
        
        // M.T.
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("rs2"));
        
        // M.T.
        // Include the root group-membership resource for Group OSCORE.
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource));
        
        // M.T:
        // For each OSCORE group, include the associated group-membership resource and its sub-resources
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/pub-key"));
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
  	    Resource groupOSCORERootMembership = new GroupOSCORERootMembershipResource(rootGroupMembershipResource); // M.T.
  	    
  	    /*
  	     * For each OSCORE group, create the associated group-membership resource and its sub-resources
  	    */
        // Group-membership resource - The name of the OSCORE group is used as resource name
        Resource join = new GroupOSCOREJoinResource(groupName); // M.T.
        // Add the /num sub-resource
        Resource pubKeySubResource = new GroupOSCORESubResourcePubKey("pub-key"); // M.T.
        join.add(pubKeySubResource); // M.T.
        // Add the /num sub-resource
        Resource numSubResource = new GroupOSCORESubResourceNum("num"); // M.T.
        join.add(numSubResource); // M.T.
  	    // Add the /active sub-resource
        Resource activeSubResource = new GroupOSCORESubResourceActive("active"); // M.T.
  	    join.add(activeSubResource); // M.T.
  	    // Add the /policies sub-resource
        Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies"); // M.T.
  	    join.add(policiesSubResource); // M.T.
        // Add the /nodes sub-resource, as root to actually accessible per-node sub-resources
        Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes"); // M.T.
  	    join.add(nodesSubResource); // M.T.
      
  	    
        rs = new CoapServer();
        rs.add(hello);
        rs.add(temp);
        rs.add(authzInfo);
  	    rs.add(groupOSCORERootMembership); // M.T.
  	    groupOSCORERootMembership.add(join); // M.T.

      
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

    // M.T.
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
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_alg, targetedGroup.getCsAlg().AsCBOR());
        	if (targetedGroup.getCsParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_params, targetedGroup.getCsParams());
        	if (targetedGroup.getCsKeyParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_params, targetedGroup.getCsKeyParams());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_enc, targetedGroup.getCsKeyEnc());
        	
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
            
            // TODO: REMOVE DEBUG PRINT
            // System.out.println("xxx @GM sid " + subject);
            // System.out.println("yyy @GM kid " + TokenRepository.getInstance().getKid(subject));
            
            String rsNonceString = TokenRepository.getInstance().getRsnonce(subject);
            
            // TODO: REMOVE DEBUG PRINT
            // System.out.println("xxx @GM rsnonce " + rsNonceString);
            
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
        	
        	// Prepare a 'sign_info' parameter, to possibly return it in a 4.00 (Bad Request) response        	
    		CBORObject signInfo = CBORObject.NewArray();
				
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
        	
			CBORObject signInfoEntry = CBORObject.NewArray();
			CBORObject errorResponseMap = CBORObject.NewMap();
			signInfoEntry.Add(CBORObject.FromObject(targetedGroup.getGroupName())); // 'id' element
			signInfoEntry.Add(targetedGroup.getCsAlg().AsCBOR()); // 'sign_alg' element
	    	CBORObject arrayElem = targetedGroup.getCsParams(); // 'sign_parameters' element
	    	if (arrayElem == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(arrayElem);
	    	arrayElem = targetedGroup.getCsKeyParams(); // 'sign_key_parameters' element
	    	if (arrayElem == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(arrayElem);
	    	signInfoEntry.Add(targetedGroup.getCsKeyEnc()); // 'pub_key_enc' element
		    signInfo.Add(signInfoEntry);
		    errorResponseMap.Add(Constants.SIGN_INFO, signInfo);
			 
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
      	  	
          	// NEW VERSION USING the AIF-BASED ENCODING AS SINGLE INTEGER
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
            		roleIdSet = Constants.getGroupOSCORERoles(roleSet);
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
            	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        		/*
      	  		// Invalid combination of roles
      	  		if ( (roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_REQUESTER]) &&
      	  			  roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_MONITOR]))
      	  				||
      	  			 (roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_RESPONDER]) &&
      	  			  roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_MONITOR]))
      	  		   ) {
  					byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
  					return;
      	  		}
      	  		*/
        		  
        	}
      	  	
        	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
      	  	/*
      	  	if (scopeElement.getType().equals(CBORType.Integer)) {
      	  		// Only one role is specified
      	  		int index = scopeElement.AsInt32();
      	  		
      	  		// Invalid format of roles
      	  		if (index < 0) {
      	  			byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
	        		return;
      	  		}
      	  		if (index < Constants.GROUP_OSCORE_ROLES.length)
      	  			roles.add(Constants.GROUP_OSCORE_ROLES[index]);
      	  		else
      	  			roles.add(Constants.GROUP_OSCORE_ROLES[0]); // The "reserved" role is used as invalid role
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		// The CBOR Array of roles must include at least two roles
      	  		if (scopeElement.size() != 2) {
      	  			byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.Integer)) {
      	      	  		int index = scopeElement.get(i).AsInt32();
      	      	  		
      	      	  		// Invalid format of roles
      	      	  		if (index < 0) {
      	      	  			byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  							exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
      		        		return;
      	      	  		}
      	      	  		if (index < Constants.GROUP_OSCORE_ROLES.length)
      	      	  			roles.add(Constants.GROUP_OSCORE_ROLES[index]);
      	      	  		else
      	      	  			roles.add(Constants.GROUP_OSCORE_ROLES[0]); // The "reserved" role is used as invalid role
      	  			}
      	  			// Invalid format of roles
      	  			else {
      	  				byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  						exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
      	  				
      	        		return;
      	  			}
      	  		}
      	  		// Invalid combination of roles
      	  		if ( (roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_REQUESTER]) &&
      	  			  roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_MONITOR]))
      	  				||
      	  			 (roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_RESPONDER]) &&
      	  			  roles.contains(Constants.GROUP_OSCORE_ROLES[Constants.GROUP_OSCORE_MONITOR]))
      	  		   ) {
  					byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
  					return;
      	  		}
      	  		
      	  	}
      	  	*/
      	  	
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
        	// If present, this parameter must be a CBOR array
        	CBORObject getPubKeys = joinRequest.get(CBORObject.FromObject((Constants.GET_PUB_KEYS)));
        	if (getPubKeys != null) {
        		
        		// Invalid format of 'get_pub_keys'
        		if (!getPubKeys.getType().equals(CBORType.Array) ||
        			 getPubKeys.size() != 2 ||
        			!getPubKeys.get(0).getType().equals(CBORType.Array) ||
        			!getPubKeys.get(1).getType().equals(CBORType.Array) || 
        			 getPubKeys.get(1).size() != 0) {
            		
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
            		
        		}
        		
        		// Invalid format of 'get_pub_keys'
    			for (int i = 0; i < getPubKeys.get(0).size(); i++) {
    				// Possible elements of the first array have to be all integers and
    				// express a valid combination of roles encoded in the AIF data model
    				if (!getPubKeys.get(0).get(i).getType().equals(CBORType.Integer) ||
    					!validRoleCombinations.contains(getPubKeys.get(0).get(i).AsInt32())) {
    					
                		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                		return;
    					
    				}
    			}
        		
        		providePublicKeys = true;
        		
        	}
        	
        	// Retrieve the entry for the target OSCORE group, using the group name
        	GroupInfo myGroup = activeGroups.get(groupName);
        	
        	String nodeName = null;
        	byte[] senderId = null;
        	        	
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
        		
        		// client_cred must be byte string
        		if (!clientCred.getType().equals(CBORType.ByteString)) {
        			myGroup.deallocateSenderId(senderId);
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
        		}

        		// This assumes that the public key is a COSE Key
        		CBORObject coseKey = CBORObject.DecodeFromBytes(clientCred.GetByteString());
        		
        		// The public key must be a COSE key
        		if (!coseKey.getType().equals(CBORType.Map)) {
        			myGroup.deallocateSenderId(senderId);
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
        		}
        		
        		// Check that a OneKey object can be correctly built
        		OneKey publicKey;
        		try {
        			publicKey = new OneKey(coseKey);
				} catch (CoseException e) {
        			myGroup.deallocateSenderId(senderId);
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
				}
        		        		
        		// Sanity check on the type of public key        		
        		if (myGroup.getCsAlg().equals(AlgorithmID.ECDSA_256) ||
        		    myGroup.getCsAlg().equals(AlgorithmID.ECDSA_384) ||
        		    myGroup.getCsAlg().equals(AlgorithmID.ECDSA_512)) {
        			
        			// Invalid public key format
        			if (!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsParams().get(0).get(0)) || // alg capability: key type
                   		!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsParams().get(1).get(0)) || // key capability: key type
                   		!publicKey.get(KeyKeys.EC2_Curve).equals(myGroup.getCsParams().get(1).get(1)) || // key capability: curve
                   		!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsKeyParams().get(0)) || // key capability: key type
                		!publicKey.get(KeyKeys.EC2_Curve).equals(myGroup.getCsKeyParams().get(1))) // key capability: key curve
        			{ 
        					
	            			myGroup.deallocateSenderId(senderId);

                    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                			return;
                        		
                	}

        		}
        		
        		if (myGroup.getCsAlg().equals(AlgorithmID.EDDSA)) {
        			
        			// Invalid public key format
        			if (!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsParams().get(0).get(0)) || // alg capability: key type
               			!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsParams().get(1).get(0)) || // key capability: key type
               			!publicKey.get(KeyKeys.OKP_Curve).equals(myGroup.getCsParams().get(1).get(1)) || // key capability: curve
               			!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsKeyParams().get(0)) || // key capability: key type
            			!publicKey.get(KeyKeys.OKP_Curve).equals(myGroup.getCsKeyParams().get(1))) // key capability: key curve
        			{
		            			
    						myGroup.deallocateSenderId(senderId);

                    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
                			return;
                    		
            		}
        				
        		}
        		
        		// Retrieve the proof-of-possession nonce and signature from the Client
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
            	
            	// Old version of signature verification, concatenating the plain bytes rather than the serialization of CBOR byte strings
            	// byte[] rawCnonce = cnonce.GetByteString();
        		
        		// Check the proof-of-possession signature over (rsnonce | cnonce), using the Client's public key
            	CBORObject clientSignature = joinRequest.get(CBORObject.FromObject(Constants.CLIENT_CRED_VERIFY));
            	
            	// A client signature must be included for proof-of-possession for joining OSCORE groups
            	if (clientSignature == null) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
            	}

            	// The client signature must be wrapped in a binary string for joining OSCORE groups
            	if (!cnonce.getType().equals(CBORType.ByteString)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
                }
            	
            	byte[] rawClientSignature = clientSignature.GetByteString();
        		
            	PublicKey pubKey = null;
                try {
					pubKey = publicKey.AsPublicKey();
				} catch (CoseException e) {
					System.out.println(e.getMessage());
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP signature");
            		return;
				}
                if (pubKey == null) {
                	exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Failed to use the Client's public key to verify the PoP signature");
            		return;
                }

                int offset = 0;
                
                byte[] serializedScopeCBOR = scope.EncodeToBytes();
                byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(rsnonce).EncodeToBytes();
                byte[] serializedCSignNonceCBOR = cnonce.EncodeToBytes();
           	    byte[] dataToSign = new byte [serializedScopeCBOR.length + serializedGMSignNonceCBOR.length + serializedCSignNonceCBOR.length];
           	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
           	    offset += serializedScopeCBOR.length;
           	    System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
           	    offset += serializedGMSignNonceCBOR.length;
           	    System.arraycopy(serializedCSignNonceCBOR, 0, dataToSign, offset, serializedCSignNonceCBOR.length);
                
            	// Old version of signature verification, concatenating the plain bytes rather than the serialization of CBOR byte strings
           	    /*
            	byte[] dataToSign = new byte [rawScope.length + rsnonce.length + rawCnonce.length];
            	System.arraycopy(rawScope, 0, dataToSign, offset, rawScope.length);
            	offset += rawScope.length;
           	    System.arraycopy(rsnonce, 0, dataToSign, offset, rsnonce.length);
           	    offset += rsnonce.length;
           	    System.arraycopy(rawCnonce, 0, dataToSign, offset, rawCnonce.length);
           	    */
           	    
           	    int countersignKeyCurve = 0;
           	    
           	    if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_EC2))
					countersignKeyCurve = publicKey.get(KeyKeys.EC2_Curve).AsInt32();
           	    else if (publicKey.get(KeyKeys.KeyType).equals(COSE.KeyKeys.KeyType_OKP))
					countersignKeyCurve = publicKey.get(KeyKeys.OKP_Curve).AsInt32();
           	    
           	    // This should never happen, due to the previous sanity checks
           	    if (countersignKeyCurve == 0) {
           	    	exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when setting up the signature verification");
            		return;
           	    }
           	    
           	    // Invalid Client's PoP signature
           	    if (!verifySignature(countersignKeyCurve, pubKey, dataToSign, rawClientSignature)) {
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload, Constants.APPLICATION_ACE_CBOR);
            		return;
           	    }
        		
            	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the joining node
        		publicKey.add(KeyKeys.KeyId, CBORObject.FromObject(senderId));
        		
        		// Store this client's public key
        		if (!myGroup.storePublicKey(senderId, publicKey.AsCBOR())) {
        			myGroup.deallocateSenderId(senderId);
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when storing the public key");
            		return;
        			
        		}
        		
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
    			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when adding the new group member");
        		return;
        	}

        	// Create and add the sub-resource associated to the new group member
        	try {
        		valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName));
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
        	
        	
            // Respond to the Join Request
            
        	CBORObject joinResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	joinResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	// Fill the 'key' parameter
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, myGroup.getMasterSecret());
        	if (senderId != null) {
    			// The joining node is not a monitor
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.group_SenderID, senderId);
        	}
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, myGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.alg, myGroup.getAlg().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, myGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, myGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_alg, myGroup.getCsAlg().AsCBOR());
        	if (myGroup.getCsParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_params, myGroup.getCsParams());
        	if (myGroup.getCsKeyParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_params, myGroup.getCsKeyParams());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_enc, myGroup.getCsKeyEnc());
        	
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
        		
        		CBORObject coseKeySet = CBORObject.NewArray();
        		CBORObject peerRoles = CBORObject.NewArray();
        		
        		Set<CBORObject> publicKeys = myGroup.getPublicKeys();
        		
        		for (CBORObject publicKey : publicKeys) {
        			
        			// This should never happen; silently ignore
        			if (publicKey == null)
        				continue;
        			
        			byte[] peerSenderId = publicKey.get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        			
        			// Skip the public key of the just-added joining node
        			if ((senderId != null) && Arrays.equals(senderId, peerSenderId))
        				continue;
        			
        			boolean includePublicKey = false;
        			
        			// Public keys of all group members are requested
        			if (getPubKeys.get(0).size() == 0) {
        				includePublicKey = true;
        			}
        			// Only public keys of group members with certain roles are requested
        			else {
        				for (int i = 0; i < getPubKeys.get(0).size(); i++) {
        					int filterRoles = getPubKeys.get(0).get(i).AsInt32();
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
	        			coseKeySet.Add(publicKey);
	        			peerRoles.Add(myGroup.getGroupMemberRoles(peerSenderId));
        			}

        		}
        			
    			byte[] coseKeySetByte = coseKeySet.EncodeToBytes();
    			joinResponse.Add(Constants.PUB_KEYS, CBORObject.FromObject(coseKeySetByte));
    			joinResponse.Add(Constants.PEER_ROLES, peerRoles);
        			
        		
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
        	
        	byte[] responsePayload = joinResponse.EncodeToBytes();
        	String uriNodeResource = new String(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        	
        	Response coapJoinResponse = new Response(CoAP.ResponseCode.CREATED);
        	coapJoinResponse.setPayload(responsePayload);
        	coapJoinResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        	coapJoinResponse.getOptions().setLocationPath(uriNodeResource);

        	exchange.respond(coapJoinResponse);
        	
        }
    }
    
    // M.T.
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
    		CBORObject coseKeySet = CBORObject.NewArray();
    		CBORObject peerRoles = CBORObject.NewArray();
    		
    		Set<CBORObject> publicKeys = targetedGroup.getPublicKeys();
    		
    		for (CBORObject publicKey : publicKeys) {
    			
    			// This should never happen; silently ignore
    			if (publicKey == null)
    				continue;
    			
    			byte[] peerSenderId = publicKey.get(KeyKeys.KeyId.AsCBOR()).GetByteString();
    			// This should never happen; silently ignore
    			if (peerSenderId == null)
    				continue;
    			
    			coseKeySet.Add(publicKey);
    			peerRoles.Add(targetedGroup.getGroupMemberRoles(peerSenderId));
    			
    		}
    		
			byte[] coseKeySetByte = coseKeySet.EncodeToBytes();
			myResponse.Add(Constants.PUB_KEYS, CBORObject.FromObject(coseKeySetByte));
			myResponse.Add(Constants.PEER_ROLES, peerRoles);	
        	
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
        	// This parameter must be a CBOR array
        	CBORObject getPubKeys = requestCBOR.get(CBORObject.FromObject((Constants.GET_PUB_KEYS)));

    		// 'get_pub_keys' must include exactly two elements, both of which CBOR arrays
    		if (!getPubKeys.getType().equals(CBORType.Array) ||
    			 getPubKeys.size() != 2 ||
    			!getPubKeys.get(0).getType().equals(CBORType.Array) ||
    			!getPubKeys.get(1).getType().equals(CBORType.Array)) {
    			
    			valid = false;
        		
    		}

    		// Invalid format of 'get_pub_keys'
    		if (valid) {
				for (int i = 0; i < getPubKeys.get(0).size(); i++) {
					// Possible elements of the first array have to be all integers and
					// express a valid combination of roles encoded in the AIF data model
					if (!getPubKeys.get(0).get(i).getType().equals(CBORType.Integer) ||
						!validRoleCombinations.contains(getPubKeys.get(0).get(i).AsInt32())) {
							valid = false;
							break;
							
					}
				}
    		}
    		
    		// Invalid format of 'get_pub_keys'
    		if (valid) {
				for (int i = 0; i < getPubKeys.get(1).size(); i++) {
					// Possible elements of the second array have to be all
					// byte strings, specifying Sender IDs of other group members
					if (!getPubKeys.get(1).get(i).getType().equals(CBORType.ByteString)) {
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
    		
        	// Respond to the Public Key Request
            
        	CBORObject myResponse = CBORObject.NewMap();
    		CBORObject coseKeySet = CBORObject.NewArray();
    		CBORObject peerRoles = CBORObject.NewArray();
    		
    		Set<Integer> requestedRoles = new HashSet<Integer>();
    		Set<ByteBuffer> requestedSenderIDs = new HashSet<ByteBuffer>();
    		
    		// Retrieve and store the combination of roles specified in the request
    		for (int i = 0; i < getPubKeys.get(0).size(); i++) {
    			requestedRoles.add((getPubKeys.get(0).get(i).AsInt32()));
    		}
    		
    		// Retrieve and store the Sender IDs specified in the request
    		for (int i = 0; i < getPubKeys.get(1).size(); i++) {
    			byte[] myArray = getPubKeys.get(1).get(i).GetByteString();
    			ByteBuffer myBuffer = ByteBuffer.wrap(myArray);
    			requestedSenderIDs.add(myBuffer);
    		}
    		
    		Set<CBORObject> publicKeys = targetedGroup.getPublicKeys();
    		
    		for (CBORObject publicKey : publicKeys) {
    			
    			// This should never happen; silently ignore
    			if (publicKey == null)
    				continue;
    			
    			byte[] memberSenderId = publicKey.get(KeyKeys.KeyId.AsCBOR()).GetByteString();
    			// This should never happen; silently ignore
    			if (memberSenderId == null)
    				continue;

    			int memberRoles = targetedGroup.getGroupMemberRoles(memberSenderId);
    			
    			boolean include = false;
    			
    			if((requestedRoles.size() == 0) && (requestedSenderIDs.size() == 0)) {
    				include = true;
    			}
    			
    			if(!include) {
    				
    				for (Integer filter : requestedRoles) {
    					int filterRoles = filter.intValue();
    					
    					if (filterRoles == (filterRoles & memberRoles)) {
    						include = true;
    						break;
    					}	
    				}
    				
    			}
    			
    			if(!include && requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
    				include = true;
    			}
    			
    			if (include) {
    				
	    			coseKeySet.Add(publicKey);
	    			peerRoles.Add(memberRoles);
	    			
    			}
    			
    		}
    		
			byte[] coseKeySetByte = coseKeySet.EncodeToBytes();
			myResponse.Add(Constants.PUB_KEYS, CBORObject.FromObject(coseKeySetByte));
			myResponse.Add(Constants.PEER_ROLES, peerRoles);
        	
        	byte[] responsePayload = myResponse.EncodeToBytes();
        	
        	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
        	coapResponse.setPayload(responsePayload);
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

        	exchange.respond(coapResponse);

        }
        
    }
    
    
    // M.T.
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
    
    // M.T.
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
    
    // M.T.
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
    
    // M.T.
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
    
    // M.T.
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
            
        	// Respond to the Key Distribution Request
            
        	CBORObject myResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
        	myResponse.Add(Constants.GKTY, CBORObject.FromObject(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
        	
        	// This map is filled as the Group_OSCORE_Input_Material object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	byte[] senderId = Utils.hexToBytes(targetedGroup.getGroupMemberName(subject));
        	
        	// Fill the 'key' parameter
        	// Note that no Sender ID is included
        	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.group_SenderID, senderId);
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
        	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_alg, targetedGroup.getCsAlg().AsCBOR());
        	if (targetedGroup.getCsParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_params, targetedGroup.getCsParams());
        	if (targetedGroup.getCsKeyParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_params, targetedGroup.getCsKeyParams());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cs_key_enc, targetedGroup.getCsKeyEnc());
        	
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

    private static boolean OSCOREGroupCreation(String groupName, int countersignKeyCurve) throws CoseException, Exception
    {
    	// Create the OSCORE group
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };

        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

        // Group OSCORE specific values for the AEAD algorithm and HKDF
        final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
        final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;

        // Group OSCORE specific values for the countersignature
        AlgorithmID csAlg = null;
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject csParams = CBORObject.NewArray();
        CBORObject csKeyParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
    	csParams.Add(algCapabilities);
    	csParams.Add(keyCapabilities);
    	csKeyParams = keyCapabilities;       
        final CBORObject csKeyEnc = CBORObject.FromObject(Constants.COSE_KEY);
        
        final int senderIdSize = 1; // Up to 4 bytes
        
        if (activeGroups.containsKey(groupName)) {
        	
        	System.out.println("The OSCORE group " + groupName + " already exists.");
        	return false;
        	
        }
        
        // Prefix (4 byte) and Epoch (2 bytes) --- All Group IDs have the same prefix size, but can have different Epoch sizes
        // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c 
    	final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
    	byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes
    	    	
    	GroupInfo myGroup = new GroupInfo(groupName,
    									  masterSecret,
    			                          masterSalt,
    			                          groupIdPrefixSize,
    			                          groupIdPrefix,
    			                          groupIdEpoch.length,
    			                          Util.bytesToInt(groupIdEpoch),
    			                          prefixMonitorNames,
    			                          senderIdSize,
    			                          alg,
    			                          hkdf,
    			                          csAlg,
    			                          csParams,
    			                          csKeyParams,
    			                          csKeyEnc,
    			                          null);
        
    	myGroup.setStatus(true);
    	
    	byte[] mySid;
    	String myName;
    	String mySubject;
    	OneKey myKey;
    	
    	/*
    	// Generate a pair of ECDSA_256 keys and print them in base 64 (whole version, then public only)
    	
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
    	roles = Constants.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_REQUESTER);
    	
    	if (!myGroup.addGroupMember(mySid, myName, roles, mySubject))
    		return false;
    	
    	String rpkStr1 = "";
    	
    	// Store the public key of the group member with Sender ID 0x52 (ECDSA_256)
    	if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
    		rpkStr1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	
    	// Store the public key of the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
    		rpkStr1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    	
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rpkStr1)));
    	
    	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the owner
    	myKey.add(KeyKeys.KeyId, CBORObject.FromObject(mySid));
    	
    	myGroup.storePublicKey(mySid, myKey.AsCBOR());
    	
    	
    	// Add a group member with Sender ID 0x77
    	mySid = new byte[] { (byte) 0x77 };
    	if (!myGroup.allocateSenderId(mySid))
    		return false;
    	myName = myGroup.allocateNodeName(mySid);
    	mySubject = "clientY";
    	
    	roles = 0;
    	roles = Constants.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_REQUESTER);
    	roles = Constants.addGroupOSCORERole(roles, Constants.GROUP_OSCORE_RESPONDER);
    	
    	if (!myGroup.addGroupMember(mySid, myName, roles, mySubject))
    		return false;
    	
    	String rpkStr2 = "";
    	
    	// Store the public key of the group member with Sender ID 0x77 (ECDSA_256)
    	if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
    		rpkStr2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    	
    	// Store the public key of the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
    		rpkStr2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    	
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rpkStr2)));
    	
    	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the owner
    	myKey.add(KeyKeys.KeyId, CBORObject.FromObject(mySid));
    	
    	myGroup.storePublicKey(mySid, myKey.AsCBOR());
    	
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
    
    /**
     * Verify the correctness of a digital signature
     * 
     * @param countersignKeyCurve   Elliptic curve used to process the signature, encoded as in RFC 8152
     * @param pubKey   Public key of the signer, used to verify the signature
     * @param signedData   Data over which the signature has been computed
     * @param expectedSignature   Signature to verify
     * @return True if the signature verifies correctly, false otherwise
     */
    public static boolean verifySignature(int countersignKeyCurve, PublicKey pubKey, byte[] signedData, byte[] expectedSignature) {

        Signature mySignature = null;
        boolean success = false;
        
        try {
           if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
                    mySignature = Signature.getInstance("SHA256withECDSA");
           else if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
                mySignature = Signature.getInstance("NonewithEdDSA", "EdDSA");
           else {
               // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
              Assert.fail("Unsupported signature algorithm");
           }
             
         }
         catch (NoSuchAlgorithmException e) {
             System.out.println(e.getMessage());
             Assert.fail("Unsupported signature algorithm");
         }
         catch (NoSuchProviderException e) {
             System.out.println(e.getMessage());
             Assert.fail("Unsopported security provider for signature computing");
         }
         
         try {
             if (mySignature != null)
                 mySignature.initVerify(pubKey);
             else
                 Assert.fail("Signature algorithm has not been initialized");
         }
         catch (InvalidKeyException e) {
             System.out.println(e.getMessage());
             Assert.fail("Invalid key excpetion - Invalid public key");
         }
         
         try {
             if (mySignature != null) {
                 mySignature.update(signedData);
                 success = mySignature.verify(expectedSignature);
             }
         } catch (SignatureException e) {
             System.out.println(e.getMessage());
             Assert.fail("Failed signature verification");
         }
         
         return success;

    }
}
