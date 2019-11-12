package se.sics.ace.oscore.group;

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import java.util.Base64;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;

/**
 * A test case for the OSCORE profile interactions between client and server.
 * 
 * This client can be used for doing Group Joining over OSCORE.
 * Posts a Token to the GM followed by the group join procedure.
 * 
 * This should be run with TestOSCoreRSGroupOSCORE as server.
 * 
 * For testing with Peter van der Stok.
 * 
 * @author Ludwig Seitz, Rikard Höglund & Marco Tiloca
 *
 */
public class OSCoreClientGroupOSCORE {

	//Sets the port to use
	private final static int GM_PORT = CoAP.DEFAULT_COAP_PORT;
	//Set the hostname/IP of the RS (GM)
	private final static String GM_ADDRESS = "localhost";
	
	 //Additions for creating a fixed context
	private final static String uriGM = "coap://" + GM_ADDRESS;
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
		(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	//private final static byte[] context_id = { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
	private final static byte[] sid = new byte[] { 'C', '1' };
	private final static byte[] rid = new byte[] { 'G', 'M' };
	//End Additions for creating a fixed context

	private static String GM_HOST;
	//private static String REQUESTED_RESOURCE = "helloWorld";
	private static String REQUESTED_RESOURCE = "feedca570000";
	
	//Use DTLS or not (set it to false always)
	private static boolean useDTLS = false;

	// Private and public key to be used in the OSCORE group (EDDSA)
    private static String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

    //Use a string scope for the Token
    private static boolean scopeIsBytestring = true;
    
    //Public key (ECDSA)
    //private static String publicKeyStr = "piJYIBZKbV1Ll/VtH2ChKBHVXeegVeusYWTJ75MCy8v/Hwq+I1ggO+AEdZm0KqRLj4oPqI1NoRaXtY2fzE45RD6YQ78jBYYDJgECIVgg6Pmo1YUKUzzaJLn6ih7ik/ag4egeHlYKZP8TTWX37OwgAQ==";
    
    //Public key (EDDSA)
    private static String publicKeyStr = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

	
    /**
     * The cnf key used in these tests
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    @SuppressWarnings("unused")
	private static OSCoreCtx osctx;
    
    public static void main(String[] args) throws Exception {
    	// install needed cryptography providers
    	try {
    		org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
    	} catch (Exception e) {
    		System.err.println("Failed to install cryptography providers.");
    		e.printStackTrace();
    	}
    	
    	//Set OSCORE Context information
    	OSCoreCtx ctxOSCore = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext(uriGM, ctxOSCore);
		OSCoreCoapStackFactory.useAsDefault();
    	
    	OSCoreCoapStackFactory.useAsDefault();
    	
    	GM_HOST = GM_ADDRESS + ":" + GM_PORT;
    	
    	setUp();
    
    	testSuccess();
    }
    

    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    public static void setUp() throws OSException {
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnf, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null);
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    public static void testSuccess() throws Exception {
    	OneKey privateKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(publicKeyStr)));
    	
    	//Create a byte string scope for use later
    	String gid = new String("feedca570000");
     	String role1 = new String("requester");
     	String role2 = new String("responder");
    	
        CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	
        //Generate a token and simulated response from As
    	//Encrypted Token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
    	
    	//Signed Token
//        COSEparams coseP = new COSEparams(MessageTag.Sign1, 
//                AlgorithmID.EDDSA, AlgorithmID.Direct);
//    	CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(
//        		privateKey, coseP.getAlg().AsCBOR());
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        if(!scopeIsBytestring) {
        	params.put(Constants.SCOPE, CBORObject.FromObject("r_" + REQUESTED_RESOURCE));
        } else {
        	 params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        }
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        //Setting of OSCORE Context information in Token
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = "clientA".getBytes(Constants.charset);
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, keyCnf);
        byte[] serverId = "rs1".getBytes(Constants.charset);
        osc.Add(Constants.OS_SERVERID, serverId);

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
        //Post the Token to GM
        String tokenURI = "coap://" + GM_HOST + "/authz-info";
        System.out.println("Posting Token to GM at " + tokenURI);
        System.out.println("Simulated response from AS used: " + payload.ToJSONString());
        Response rsRes = OSCOREProfileRequests.postToken(
        		tokenURI, asRes);
        System.out.println("GM Response to Token post: " + Utility.arrayToString(rsRes.getPayload()));
       
        System.out.println("Due to Token post the following OSCORE Context has been generated:");
        String resourceURI = "coap://" + GM_HOST + "/" + REQUESTED_RESOURCE;
        OSCoreCtx generatedContext = HashMapCtxDB.getInstance().getContext(resourceURI);
        Utility.printContextInfo(generatedContext);
        
		//Submit a request to GM (normal request would be done here)
//		System.out.println("Performing request to GM at " + resourceURI + " (port " + GM_PORT + ")");
		CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				resourceURI, GM_PORT));
//		Request helloReq = new Request(CoAP.Code.POST);
//		helloReq.setPayload("HELLO");
//		helloReq.getOptions().setOscore(new byte[0]);
//		CoapResponse helloRes = c.advanced(helloReq);
//		System.out.println("Received response from GM:" + helloRes.getResponseText());
		//Note: Re-enable these 8 lines above to have the normal request functionality
		
		
		/* Create and perform Join Request below */
		
		//First set up some parameters
		boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	//Now proceed with creating Join request
		
		System.out.println("Performing Join request using OSCORE to GM at " + resourceURI);
        c.setURI(resourceURI);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
        	requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
        	
        }
        
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);
        if(!useDTLS) {
        	joinReq.getOptions().setOscore(Bytes.EMPTY); //Enable OSCORE for Join request
        }
        
        //Transmit the Join request
        
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
        
        byte[] responsePayload = r2.getPayload();

        System.out.println("Received response to Join req from GM: " + r2.getResponseText());
        
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        if(myMap.size() != 10) {
        	System.out.println("Received bad response from GM: " + r2.getResponseText());
        } else {
        	System.out.println("Received Join response from GM: " + joinResponse.toString());
        }

        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject((int)32));        
        
        Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        CBORObject coseKeySetArray = null;
        if (askForPubKeys) {
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte); 	
        }
        else {
        	System.err.println("Join response did not contain pub_keys!");
        }
        
        
        /* Group OSCORE Context derivation below */
        
        //Defining variables to hold the information before derivation
        
        //Algorithm
        AlgorithmID algo = null;
        CBORObject alg_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.alg);
        if(alg_param.getType() == CBORType.TextString) {
        	algo = AlgorithmID.valueOf(alg_param.AsString());
        } else if(alg_param.getType() == CBORType.Number) {
        	algo = AlgorithmID.FromCBOR(alg_param);
        }
        
        //KDF
        AlgorithmID kdf = null;
        CBORObject kdf_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.hkdf);
        if(kdf_param.getType() == CBORType.TextString) {
        	kdf = AlgorithmID.valueOf(kdf_param.AsString());
        } else if(kdf_param.getType() == CBORType.Number) {
        	kdf = AlgorithmID.FromCBOR(kdf_param);
        }
        
    	//Algorithm for the countersignature
        AlgorithmID alg_countersign = null;
        CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
        if(alg_countersign_param.getType() == CBORType.TextString) {
        	alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
        } else if(alg_countersign_param.getType() == CBORType.Number) {
        	alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
        }

        //Parameter for the countersignature
        Integer par_countersign = null;
        CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
        if(par_countersign_param.getType() == CBORType.Map) {
        	par_countersign = par_countersign_param.get(KeyKeys.OKP_Curve.AsCBOR()).AsInt32();
        } else {
        	System.err.println("Unknown par_countersign value!");
        }
    
    	//Master secret
    	CBORObject master_secret_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.ms);
    	byte[] master_secret = null;
    	if(master_secret_param.getType() == CBORType.ByteString) {
    		master_secret = master_secret_param.GetByteString();
   		}
    	
    	//Master salt
    	CBORObject master_salt_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.salt);
    	byte[] master_salt = null;
    	if(master_salt_param.getType() == CBORType.ByteString) {
    		master_salt = master_salt_param.GetByteString();
   		}
 
    	//Sender ID
    	byte[] sid = null;
    	CBORObject sid_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.clientId);
    	if(sid_param.getType() == CBORType.ByteString) {
    		sid = sid_param.GetByteString();
    	}
    	
    	//Group ID / Context ID
    	CBORObject group_identifier_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.contextId);
    	byte[] group_identifier = null;
    	if(group_identifier_param.getType() == CBORType.ByteString) {
    		group_identifier = group_identifier_param.GetByteString();
    	}
    	
    	//RPL (replay window information)
    	CBORObject rpl_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.rpl);
    	int rpl = 32; //Default value
    	if(rpl_param != null && rpl_param.getType() == CBORType.Number) {
    		rpl = rpl_param.AsInt32();
    	}
    	
    	//Set up private & public keys for sender (not from response but set by client)
    	String sid_private_key_string = groupKeyPair;
    	OneKey sid_private_key;
       	sid_private_key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));

    	//Now derive the actual context
    	
    	GroupOSCoreCtx oscoreCtx = null;
		try {
			oscoreCtx = new GroupOSCoreCtx(master_secret, true, algo, sid, kdf, rpl, 
					master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
		} catch (OSException e) {
			System.err.println("Failed to derive Group OSCORE Context!");
			e.printStackTrace();
		}
		
		//Finally add the recipient contexts from the coseKeySetArray
		for(int i = 0 ; i < coseKeySetArray.size() ; i++) {
			
			CBORObject key_param = coseKeySetArray.get(i);
			
	    	byte[] rid = null;
	    	CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
	    	if(rid_param.getType() == CBORType.ByteString) {
	    		rid = rid_param.GetByteString();
	    	}
			
			OneKey recipient_key = new OneKey(key_param);
			
			oscoreCtx.addRecipientContext(rid, recipient_key);
		}
		
		//Print information about the created context
		System.out.println();
		System.out.println("Generated Group OSCORE Context from received information:");
		Utility.printContextInfo(oscoreCtx);

       
    }

    
    

}
