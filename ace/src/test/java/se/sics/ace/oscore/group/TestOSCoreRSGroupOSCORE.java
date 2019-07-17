package se.sics.ace.oscore.group;

import java.io.File;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.group.AltTestOSCoreRSGroupOSCORE.GroupOSCOREJoinResource;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.AsRequestCreationHints;

/**
 * A RS for testing the OSCORE profile of ACE (https://datatracker.ietf.org/doc/draft-ietf-ace-oscore-profile)
 * 
 * Server for testing Group Joining over OSCORE.
 * Should first receive a Token to authz-info.
 * 
 * Followed by a request to initiate the Join procedure,
 * the server will reply with the Join response.
 * 
 * For testing with Peter van der Stok.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class TestOSCoreRSGroupOSCORE {
	
	//Sets the port to use
	private final static int PORT = CoAP.DEFAULT_COAP_PORT;
	
	// Up to 4 bytes, same for all the OSCORE Group of the Group Manager
	private final static int groupIdPrefixSize = 4; 
	
	// TODO: When included in the referenced Californium, use californium.elements.util.Bytes rather than Integers as map keys 
	static Map<Integer, GroupInfo> activeGroups = new HashMap<>();

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
    
    private static OscoreAuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;  
    
    /**
     * The CoAP OSCORE server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
    	OSCoreCoapStackFactory.useAsDefault();
    	
    	//Install needed cryptography providers
        org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
    	
      //Set up token repository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_helloWorld", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put("feedca570000", actions3);
        myScopes.put("r_feedca570000", myResource3);
        
        //Create the OSCORE Group(s)
        OSCOREGroupCreation();
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);

//        // M.T.
//        Set<String> auds = new HashSet<>();
//        auds.add("rs1"); // Simple test audience
//        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
//        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes);
//        
//        // M.T.
//        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
//        valid.setGMAudiences(Collections.singleton("rs1"));
//        
//        // M.T.
//        // Include this resource as a join resource for Group OSCORE.
//        // The resource name is the zeroed-epoch Group ID of the OSCORE group.
//        valid.setJoinResources(Collections.singleton("feedca570000"));
        
        byte[] key128a 
            = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      
               
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());

        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token files
        new File(tokenFile).delete();
        
      //Set up the inner Authz-Info library
      ai = new OscoreAuthzInfo(Collections.singletonList("TestAS"), 
                new KissTime(), null, valid, ctx,
                tokenFile, valid, false);
      
      //Add a test token to authz-info
      byte[] key128
          = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      Map<Short, CBORObject> params = new HashMap<>(); 
      params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
      params.put(Constants.AUD, CBORObject.FromObject("rs1"));
      params.put(Constants.CTI, CBORObject.FromObject(
              "token1".getBytes(Constants.charset)));
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
      payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
      byte[] n1 = new byte[8];
      new SecureRandom().nextBytes(n1);
      payload.Add(Constants.CNONCE, n1);
      
      ai.processMessage(new LocalMessage(0, null, null, token.encode(ctx)));

      AsRequestCreationHints archm 
          = new AsRequestCreationHints(
                  "coaps://blah/authz-info/", null, false, false);
      Resource hello = new HelloWorldResource();
      Resource temp = new TempResource();
      Resource authzInfo = new CoapAuthzInfo(ai);
      Resource manage = new ManageResource();
      Resource join = new GroupOSCOREJoinResource("feedca570000"); // M.T.
      
      OSCoreCoapStackFactory.useAsDefault();
      rs = new CoapServer(PORT);
      rs.add(hello);
      rs.add(temp);
      rs.add(manage);
      rs.add(join);
      rs.add(authzInfo);
      

      dpd = new CoapDeliverer(rs.getRoot(), null, archm); 

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
     * Definition of the Group OSCORE Join Resource
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
            getAttributes().setTitle("Group OSCORE Join Resource " + resId);
        }

        @Override
        public void handleGET(CoapExchange exchange) {
        	System.out.println("GET request reached the GM");
        	exchange.respond("GET request reached the GM");
        }
        
        @Override
        public void handlePOST(CoapExchange exchange) {
            
        	System.out.println("POST request reached the GM");
        	
        	Set<String> roles = new HashSet<>();
        	boolean providePublicKeys = false;
        	
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	CBORObject joinRequest = CBORObject.DecodeFromBytes(requestPayload);
        	
        	if (!joinRequest.getType().equals(CBORType.Map))
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The payload of the join request must be a CBOR Map");
        		
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
        	CBORObject scope = joinRequest.get("scope");
        	
        	if (scope == null) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Scope must be included for joining OSCORE groups");
        		return;
        	}
        	if (!scope.getType().equals(CBORType.ByteString)) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Scope must be wrapped in a binary string for joining OSCORE groups");
        		return;
            }
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
        		return;
            }
        	
        	if (cborScope.size() != 2) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
        		return;
            }
        	
        	// Retrieve the zeroed-epoch Group ID of the OSCORE group
        	String scopeStr;
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		scopeStr = scopeElement.AsString();

      	  		if (!scopeStr.equals(exchange.getRequestOptions().getUriPathString())) {
	  				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The Group ID in 'scope' is not pertinent for this join resource");
	  				return;
	  			}      	  		
      	  	}
      	  	else {
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
        		return;
      	  	}
      	  	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		roles.add(scopeElement.AsString());
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The CBOR Array of roles must include at least two roles");
            		return;
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString))
      	  				roles.add(scopeElement.get(i).AsString());
      	  			else {
      	  				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The CBOR Array of roles must include at least two roles");
      	        		return;
      	  			}
      	  		}
      	  	}
      	  	else {
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of roles");
        		return;
      	  	}
        	
        	// Retrieve 'get_pub_keys'
        	// If present, this parameter must be an empty CBOR array
        	CBORObject getPubKeys = joinRequest.get("get_pub_keys");
        	if (getPubKeys != null) {
        		
        		if (!getPubKeys.getType().equals(CBORType.Array) && getPubKeys.size() != 0) {
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "get_pub_keys must be an empty array");
            		return;
        		}
        		
        		providePublicKeys = true;
        		
        	}
        	
        	// The first 'groupIdPrefixSize' pairs of characters are the Group ID Prefix.
        	// This string is surely hexadecimal, since it passed the early check against the URI path to the join resource.
        	String prefixStr = scopeStr.substring(0, 2 * groupIdPrefixSize);
        	byte[] prefixByteStr = hexStringToByteArray(prefixStr);
        	
        	// Retrieve the entry for the target group, using the Group ID Prefix
        	GroupInfo myGroup = activeGroups.get(Integer.valueOf(GroupInfo.bytesToInt(prefixByteStr)));
        	
        	// Assign a new Sender ID to the joining node.
        	// For the sake of testing, a particular Sender ID is used as known to be available.
            byte[] senderId = new byte[] { (byte) 0x25 };
        	myGroup.allocateSenderId(senderId);        	
        	
        	// Retrieve 'client_cred'
        	CBORObject clientCred = joinRequest.get("client_cred");
        	
        	if (clientCred == null) {
        	
        		// TODO: check if the Group Manager already owns this client's public key, otherwise reply with 4.00
        		
        	}
        	else {
        		
        		if (!clientCred.getType().equals(CBORType.ByteString)) {
            		myGroup.deallocateSenderId(senderId);
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "client_cred must be byte string");
            		return;
        		}

        		// This assumes that the public key is a COSE Key
        		CBORObject coseKey = CBORObject.DecodeFromBytes(clientCred.GetByteString());
        		
        		if (!coseKey.getType().equals(CBORType.Map)) {
            		myGroup.deallocateSenderId(senderId);
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "the public key must be a COSE key");
            		return;
        		}
        		
        		// Check that a OneKey object can be correctly built
        		OneKey publicKey;
        		try {
        			publicKey = new OneKey(coseKey);
				} catch (CoseException e) {
					System.err.println(e.getMessage());
					myGroup.deallocateSenderId(senderId);
					exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "invalid public key format");
            		return;
				}
        		        		
        		// Sanity check on the type of public key
        		// TODO: The "Bad Request" response should actually tell the joining node the exact algorithm and parameters
        		
        		if (myGroup.getCsAlg().equals(AlgorithmID.ECDSA_256) ||
        		    myGroup.getCsAlg().equals(AlgorithmID.ECDSA_384) ||
        		    myGroup.getCsAlg().equals(AlgorithmID.ECDSA_512)) {
        			
        			if (!publicKey.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2) ||
        				!publicKey.get(KeyKeys.EC2_Curve).equals(myGroup.getCsKeyParams().get(CBORObject.FromObject(KeyKeys.EC2_Curve)))) {
        				
                			myGroup.deallocateSenderId(senderId);
                			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "invalid public key format");
                			return;
                		
        			}
        		}
        		
        		if (myGroup.getCsAlg().equals(AlgorithmID.EDDSA)) {
        			
        			if (!publicKey.get(KeyKeys.OKP_Curve).equals(myGroup.getCsParams().get(CBORObject.FromObject(KeyKeys.OKP_Curve))) ||
           				!publicKey.get(KeyKeys.KeyType).equals(myGroup.getCsKeyParams().get(CBORObject.FromObject(KeyKeys.KeyType))) ||
        				!publicKey.get(KeyKeys.OKP_Curve).equals(myGroup.getCsKeyParams().get(CBORObject.FromObject(KeyKeys.OKP_Curve)))) {

                			myGroup.deallocateSenderId(senderId);

                			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "invalid public key format");
                			return;
                		
        			}
        				
        		}
        				
            	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the joining node
        		publicKey.add(KeyKeys.KeyId, CBORObject.FromObject(senderId));
        		
        		// Store this client's public key
        		if (!myGroup.storePublicKey(GroupInfo.bytesToInt(senderId), publicKey.AsCBOR())) {
        			myGroup.deallocateSenderId(senderId);
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "error when storing the public key");
            		return;
        			
        		}
        		
        	}
        	
            // Respond to the Join Request
            
        	CBORObject joinResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Security_Context object.
        	// NOTE: '0' is a temporary value.
        	joinResponse.Add("kty", CBORObject.FromObject(0));
        	
        	// This map is filled as the Group_OSCORE_Security_Context object, as defined in draft-ace-key-groupcomm-oscore
        	CBORObject myMap = CBORObject.NewMap();
        	
        	// Fill the 'key' parameter
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.ms, myGroup.getMasterSecret());
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.clientId, senderId);
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.hkdf, myGroup.getHkdf());
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.alg, myGroup.getAlg());
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.salt, myGroup.getMasterSalt());
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.contextId, myGroup.getGroupId());
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.cs_alg, myGroup.getCsAlg());
        	if (myGroup.getCsParams().size() != 0)
        		myMap.Add(GroupOSCORESecurityContextObjectParameters.cs_params, myGroup.getCsParams());
        	if (myGroup.getCsKeyParams().size() != 0)
        		myMap.Add(GroupOSCORESecurityContextObjectParameters.cs_key_params, myGroup.getCsKeyParams());
        	
        	joinResponse.Add("key", myMap);
        	
        	// If backward security has to be preserved:
        	//
        	// 1) The Epoch part of the Group ID should be incremented
        	// myGroup.incrementGroupIdEpoch();
        	//
        	// 2) The OSCORE group should be rekeyed

        	
        	// CBOR Value assigned to the coap_group_oscore profile.
        	// NOTE: '0' is a temporary value.
        	joinResponse.Add("profile", CBORObject.FromObject(0));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	joinResponse.Add("exp", CBORObject.FromObject(1000000));
        	
        	// NOTE: this is currently skipping the inclusion of the optional parameter 'group_policies'.
        	if (providePublicKeys) {
        		
        		CBORObject coseKeySet = CBORObject.NewArray();
        		
        		for (Integer i : myGroup.getUsedSenderIds()) {
        			
        			// Skip the entry of the just-added joining node 
        			if (i.equals(GroupInfo.bytesToInt(senderId)))
        				continue;
        			
        			CBORObject coseKeyPeer = myGroup.getPublicKey(i);
        			coseKeySet.Add(coseKeyPeer);
        			
        		}
        		
        		if (coseKeySet.size() > 0) {
        			
        			byte[] coseKeySetByte = coseKeySet.EncodeToBytes();
        			joinResponse.Add("pub_keys", CBORObject.FromObject(coseKeySetByte));
        			
        		}
        		
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
        	
        	byte[] responsePayload = joinResponse.EncodeToBytes();
        	exchange.respond(ResponseCode.CREATED, responsePayload, MediaTypeRegistry.APPLICATION_CBOR);
        	
        }
    }
    
    /**
     * @param str  the hex string
     * @return  the byte array
     * @str   the hexadecimal string to be converted into a byte array
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
    
    private static void OSCOREGroupCreation() throws CoseException
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
        AlgorithmID csAlg;
        Map<KeyKeys, CBORObject> csParamsMap = new HashMap<>();
        Map<KeyKeys, CBORObject> csKeyParamsMap = new HashMap<>();
        
        // ECDSA_256
        //csAlg = AlgorithmID.ECDSA_256;
        //csKeyParamsMap.put(KeyKeys.KeyType, KeyKeys.KeyType_EC2);        
        //csKeyParamsMap.put(KeyKeys.EC2_Curve, KeyKeys.EC2_P256);
        
        // EDDSA (Ed25519)
        csAlg = AlgorithmID.EDDSA;
        csParamsMap.put(KeyKeys.OKP_Curve, KeyKeys.OKP_Ed25519);
        csKeyParamsMap.put(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
        csKeyParamsMap.put(KeyKeys.OKP_Curve, KeyKeys.OKP_Ed25519);

        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
        
        final int senderIdSize = 1; // Up to 4 bytes

        // Prefix (4 byte) and Epoch (2 bytes) --- All Group IDs have the same prefix size, but can have different Epoch sizes
        // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c 
    	final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
    	byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes
    	
    	GroupInfo myGroup = new GroupInfo(masterSecret,
    			                          masterSalt,
    			                          groupIdPrefixSize,
    			                          groupIdPrefix,
    			                          groupIdEpoch.length,
    			                          GroupInfo.bytesToInt(groupIdEpoch),
    			                          senderIdSize,
    			                          alg,
    			                          hkdf,
    			                          csAlg,
    			                          csParams,
    			                          csKeyParams);
        
    	byte[] mySid;
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
    	myGroup.allocateSenderId(mySid);	
    	
    	// Store the public key of the group member with Sender ID 0x52 (ECDSA_256)
    	//String rpkStr1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	  	
    	// Store the public key of the group member with Sender ID 0x52 (EDDSA)
    	String rpkStr1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rpkStr1)));
    	
    	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the owner
    	myKey.add(KeyKeys.KeyId, CBORObject.FromObject(mySid));
    	myGroup.storePublicKey(GroupInfo.bytesToInt(mySid), myKey.AsCBOR());
    	
    	
    	// Add a group member with Sender ID 0x77
    	mySid = new byte[] { (byte) 0x77 };
    	myGroup.allocateSenderId(mySid);
    	
    	// Store the public key of the group member with Sender ID 0x77 (ECDSA_256)
    	//String rpkStr2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    	
    	// Store the public key of the group member with Sender ID 0x77 (EDDSA)
    	String rpkStr2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    	myKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rpkStr2)));
    	
    	// Set the 'kid' parameter of the COSE Key equal to the Sender ID of the owner
    	myKey.add(KeyKeys.KeyId, CBORObject.FromObject(mySid));
    	myGroup.storePublicKey(GroupInfo.bytesToInt(mySid), myKey.AsCBOR()); 	
    	
    	
    	// Add this OSCORE group to the set of active groups
    	// If the groupIdPrefix is 4 bytes in size, the map key can be a negative integer, but it is not a problem
    	activeGroups.put(Integer.valueOf(GroupInfo.bytesToInt(groupIdPrefix)), myGroup);
    	
    }


}
