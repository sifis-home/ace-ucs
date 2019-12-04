package se.sics.prototype.apps;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.prototype.support.KeyStorage;
import se.sics.prototype.support.Util;

/**
 * A stand-alone application for Client->AS followed by Client->GM
 * communication using the OSCORE profile.
 * 
 * First the client will request a Token from the AS,
 * it will then post it to the GM and then proceed with
 * the Group Joining procedure.
 * 
 * @author Rikard Höglund
 *
 */
public class OscoreAsRsClient {

	/* Information:
	 Clients: Server1, Server2, Server3, Server4, Server5, Server6, Client1, Client2
	 Groups: GroupA (aaaaaa570000), GroupB (bbbbbb570000)
	 */
	
	//Sets the GM port to use
	private final static int GM_PORT = CoAP.DEFAULT_COAP_PORT + 100;
	//Sets the GM hostname/IP to use
	private final static String GM_HOST = "localhost";
	
	//Sets the AS port to use
	private final static int AS_PORT = CoAP.DEFAULT_COAP_PORT;
	//Sets the AS hostname/IP to use
	private final static String AS_HOST = "localhost";
	
	/**
	 * Main method for Token request followed by Group joining
	 * 
	 * @throws CoseException 
	 */
	public static void main(String[] args) throws CoseException {
		
		//Set member name from command line argument
		String memberName;
		if(args.length > 0) {
			memberName = args[0];
		} else {
			memberName = "Server2";	
		}
		
		//Set group to join based on the member name
		String group = "";
		switch(memberName) {
		case "Client1":
		case "Server1":
		case "Server2":
		case "Server3":
			group = "aaaaaa570000";
			break;
		case "Client2":
		case "Server4":
		case "Server5":
		case "Server6":
			group = "bbbbbb570000";
			break;
		default:
			System.err.println("Error: Invalid member name specified!");
			System.exit(1);
			break;		
		}

		//Set public/private key to use in the group
		String publicPrivateKey;
		publicPrivateKey = KeyStorage.publicPrivateKeys.get(memberName);
		
		//Set key (OSCORE master secret) to use towards AS
		byte[] keyToAS;
		keyToAS = KeyStorage.memberAsKeys.get(memberName);
		
		System.out.println("Configured with parameters:");
		System.out.println("\tAS: " + AS_HOST + ":" + AS_PORT);
		System.out.println("\tGM: " + GM_HOST + ":" + GM_PORT);
		System.out.println("\tMember name: " + memberName);
		System.out.println("\tGroup: " + group);
		System.out.println("\tGroup Key: " + publicPrivateKey);
		System.out.println("\tKey to AS: " + StringUtil.byteArray2Hex(keyToAS));

		
		//Request Token from AS
		Response responseFromAS = null;
		try {
			responseFromAS = requestToken(memberName, group, keyToAS);
		} catch (OSException | AceException e) {
			System.err.print("Token request procedure failed: ");
			e.printStackTrace();
		}	
		
		//Post Token to GM and perform Group joining
        try {
            postTokenAndJoin(memberName, group, publicPrivateKey, responseFromAS);
        } catch (IllegalStateException | InvalidCipherTextException | CoseException | AceException | OSException
                | ConnectorException | IOException e) {
            System.err.print("Join procedure failed: ");
            e.printStackTrace();
        }
    }
	
	/**
	 * Request a Token from the AS.
	 * 
	 * @param memberName
	 * @param group
	 * @param keyToAS
	 * @throws OSException
	 * @throws AceException
	 */
	public static Response requestToken(String memberName, String group, byte[] keyToAS) throws OSException, AceException {
		
		/* Configure parameters */
		
		String clientID = memberName;
		String groupName = group;		
        byte[] key128 = keyToAS; //KeyStorage.memberAsKeys.get(memberName);// {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        String tokenURI = "coap://" + AS_HOST + ":" + AS_PORT + "/token";
        
        /* Set byte string scope */
        
		String gid = new String(groupName);
        String role1 = new String("requester");
        String role2 = new String("responder");

        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
        CBORObject cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(role1);
        cborArrayRoles.Add(role2);
        cborArrayScope.Add(cborArrayRoles);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
		
        /* Perform Token request */
        
        System.out.println("Performing Token request to AS.");
        System.out.println("AS Token resource is at: " + tokenURI);
        
		CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs2"),
                CBORObject.FromObject(byteStringScope), null);
        
        OSCoreCtx ctx = new OSCoreCtx(key128, true, null, 
                clientID.getBytes(Constants.charset),
                "AS".getBytes(Constants.charset),
                null, null, null, null);
        
        Response response = OSCOREProfileRequests.getToken(
                tokenURI, params, ctx);
        
        /* Parse and print response */
        
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        //Map<Short, CBORObject> map = Constants.getParams(res);
        //System.out.println(map);

        System.out.println("Received response from AS to Token request: " + res.toString());
        
        //Fix the structure of the response from the AS as the first element should be an array
        CBORObject first = res.get(CBORObject.FromObject(1));
        CBORObject firstAsCBORArray = CBORObject.DecodeFromBytes(first.GetByteString());
        //System.out.println(firstAsCBORArray.toString());
        res.Remove(CBORObject.FromObject(1));
        res.Add(CBORObject.FromObject(1), firstAsCBORArray);
        System.out.println("Fixed response from AS to Token request: " + res.toString());
        
        response.setPayload(res.EncodeToBytes());
        return response;
	}
	
	/**
	 * Post to Authz-Info, then perform join request using multiple roles.
     * Uses the ACE OSCORE Profile.
	 * 
	 * @param memberName
	 * @param group
	 * @param publicPrivateKey
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws CoseException
	 * @throws AceException
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 */
    public static void postTokenAndJoin(String memberName, String group, String publicPrivateKey, Response responseFromAS) throws IllegalStateException, InvalidCipherTextException, CoseException, AceException, OSException, ConnectorException, IOException {

        /* Configure parameters for the join request */

        boolean askForSignInfo = true;
        boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;

        // Generate private and public key to be used in the OSCORE group by the joining client (EDDSA)
        InstallCryptoProviders.installProvider();
        String groupKeyPair = publicPrivateKey;// = InstallCryptoProviders.getCounterSignKey(); //"pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

        // Set EDDSA with curve Ed25519 for countersignatures
        int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();

        // The cnf key used in these tests
        byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        //The AS <-> RS key used in these tests
        byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        
        String groupName = group; //"bbbbbb570000";
        String audience = "rs2";
        String asName = "AS";
        String clientID = memberName; //"clientA";
        String cti = "token4JoinMultipleRolesDeriv" + clientID;

        String gmBaseURI = "coap://" + GM_HOST + ":" + GM_PORT + "/";
        String authzInfoURI = gmBaseURI + "authz-info";
        String joinResourceURI = gmBaseURI + groupName;

        System.out.println("Performing Token post to GM followed by Join request.");
        System.out.println("GM join resource is at: " + joinResourceURI);

        /* Prepare ACE Token generated by the client */

//        //Generate a token (update to get Token from AS here instead)
//        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
//        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
//        Map<Short, CBORObject> params = new HashMap<>(); 
//
        //Create a byte string scope for use later
        String gid = new String(groupName);
        String role1 = new String("requester");
        String role2 = new String("responder");

        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
        CBORObject cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(role1);
        cborArrayRoles.Add(role2);
        cborArrayScope.Add(cborArrayRoles);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();

//        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
//        params.put(Constants.AUD, CBORObject.FromObject(audience));
//        params.put(Constants.CTI, CBORObject.FromObject(cti.getBytes(Constants.charset))); //Need different CTIs
//        params.put(Constants.ISS, CBORObject.FromObject(asName));
//
//        CBORObject osc = CBORObject.NewMap();
//        byte[] clientId = clientID.getBytes(Constants.charset); //Need different client IDs
//        osc.Add(Constants.OS_CLIENTID, clientId);
//        osc.Add(Constants.OS_MS, keyCnf);
//        byte[] serverId = audience.getBytes(Constants.charset);
//        osc.Add(Constants.OS_SERVERID, serverId);
//
//        CBORObject cnf = CBORObject.NewMap();
//        cnf.Add(Constants.OSCORE_Security_Context, osc);
//        params.put(Constants.CNF, cnf);
//        CWT token = new CWT(params);
//        CBORObject payload = CBORObject.NewMap();
//        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
//        payload.Add(Constants.CNF, cnf);
//        Response asRes = new Response(CoAP.ResponseCode.CREATED);
//        asRes.setPayload(payload.EncodeToBytes());

        /* Post Token to GM */

        CBORObject res = CBORObject.DecodeFromBytes(responseFromAS.getPayload());
        System.out.println("Performing Token request to GM. Response from AS was: " + res.toString());

        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(authzInfoURI, responseFromAS, askForSignInfo, askForPubKeyEnc);

        /* Check response from GM to Token post */

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext(joinResourceURI));

        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());

        System.out.println("Receved response from GM to Token post: " + rsPayload.toString());

        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()

        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();

        @SuppressWarnings("unused")
        CBORObject signInfo = null;
        @SuppressWarnings("unused")
        CBORObject pubKeyEnc = null;

        if (askForSignInfo) {
            signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        }

        if (askForPubKeyEnc) {
            pubKeyEnc = rsPayload.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        }

        /* Now proceed to build join request to GM */

        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(joinResourceURI, CoAP.DEFAULT_COAP_PORT));

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

            // Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);

            // Add the signature computed over (rsnonce | cnonce), using the Client's private key
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            byte [] dataToSign = new byte [gm_sign_nonce.length + cnonce.length];
            System.arraycopy(gm_sign_nonce, 0, dataToSign, 0, gm_sign_nonce.length);
            System.arraycopy(cnonce, 0, dataToSign, gm_sign_nonce.length, cnonce.length);

            byte[] clientSignature = Util.computeSignature(privKey, dataToSign, countersignKeyCurve);

            if (clientSignature != null)
                requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
            else
                Assert.fail("Computed signature is empty");

        }

        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);

        /* Send to join request to GM */

        System.out.println("Performing Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);

        /* Parse response to Join request from GM */

        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

        CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

        //The following two lines are useful for generating the Group OSCORE context
        Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(keyMap));
        GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 

        System.out.println("Receved response from GM to Join request: " + joinResponse.toString());

        /* Parse the Join response in detail */

        Util.printJoinResponse(joinResponse);

        /* Generate a Group OSCORE security context from the Join response */

        CBORObject coseKeySetArray = CBORObject.NewArray();
        if(joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS))) {
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        }
        
        GroupOSCoreCtx groupOscoreCtx = Util.generateGroupOSCOREContext(contextObject, coseKeySetArray, groupKeyPair);

        System.out.println();
        //System.out.println("Generated Group OSCORE Context:");
        Utility.printContextInfo(groupOscoreCtx);

    }
}
