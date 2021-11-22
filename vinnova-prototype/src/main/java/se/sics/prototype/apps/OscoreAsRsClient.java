package se.sics.prototype.apps;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObject;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
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
	
	//Sets the default GM port to use
	private static int GM_PORT = CoAP.DEFAULT_COAP_PORT + 100;
	//Sets the default GM hostname/IP to use
	private static String GM_HOST = "localhost";
	
	//Sets the default AS port to use
	private static int AS_PORT = CoAP.DEFAULT_COAP_PORT;
	//Sets the default AS hostname/IP to use
	private static String AS_HOST = "localhost";
	
	//Multicast IP for Group A
	static final InetAddress groupA_multicastIP = new InetSocketAddress("224.0.1.191", 0).getAddress();
	
	//Multicast IP for Group B
	static final InetAddress groupB_multicastIP = new InetSocketAddress("224.0.1.192", 0).getAddress();
	
    static HashMapCtxDB db = new HashMapCtxDB();

    // Each set of the list refers to a different size of Recipient IDs.
    // The element with index 0 includes as elements Recipient IDs with size 1 byte.
    private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();

    private static final String rootGroupMembershipResource = "ace-group";

	/**
	 * Main method for Token request followed by Group joining
	 * 
	 * @throws CoseException 
	 */
	public static void main(String[] args) throws CoseException, URISyntaxException {
		
		//Set member name, AS and GM to use from command line arguments
		String memberName = "Client1";
		for(int i = 0 ; i < args.length ; i += 2) {
			if(args[i].equals("-name")) {
				memberName = args[i + 1];
			} else if(args[i].equals("-gm")) {
				GM_HOST = new URI(args[i + 1]).getHost();
				GM_PORT = new URI(args[i + 1]).getPort();
			} else if(args[i].equals("-as")) {
				AS_HOST = new URI(args[i + 1]).getHost();
				AS_PORT = new URI(args[i + 1]).getPort();
			}
		}
		
		//Explicitly enable the OSCORE Stack
		if(CoapEndpoint.isDefaultCoapStackFactorySet() == false) {
			OSCoreCoapStackFactory.useAsDefault(db);
		}
		
        for (int i = 0; i < 4; i++) {
            // Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
            // The set with index 0 refers to Sender IDs with size 1 byte
            usedRecipientIds.add(new HashSet<Integer>());
        }

		//Set group to join based on the member name
		String group = "";
		InetAddress multicastIP = null;
		switch(memberName) {
		case "Client1":
		case "Server1":
		case "Server2":
		case "Server3":
			group = "aaaaaa570000";
			multicastIP = groupA_multicastIP;
			break;
		case "Client2":
		case "Server4":
		case "Server5":
		case "Server6":
			group = "bbbbbb570000";
			multicastIP = groupB_multicastIP;
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

		printPause(memberName, "Will now request Token from AS");
		
		//Request Token from AS
		Response responseFromAS = null;
		try {
			responseFromAS = requestToken(memberName, group, keyToAS);
		} catch (OSException | AceException e) {
			System.err.print("Token request procedure failed: ");
			e.printStackTrace();
		}
		
		printPause(memberName, "Will now post Token to Group Manager and perform group joining");
		
		//Post Token to GM and perform Group joining
		GroupCtx derivedCtx = null;
        try {
        	derivedCtx = postTokenAndJoin(memberName, group, publicPrivateKey, responseFromAS);
        } catch (IllegalStateException | InvalidCipherTextException | CoseException | AceException | OSException
                | ConnectorException | IOException e) {
            System.err.print("Join procedure failed: ");
            e.printStackTrace();
        }
        
        //Now start the Group OSCORE Client or Server application with the derived context
        try {
	        if(memberName.equals("Client1") || memberName.equals("Client2")) {
	        	GroupOscoreClient.start(derivedCtx, multicastIP);
	        } else {
	        	GroupOscoreServer.start(derivedCtx, multicastIP);
	        }
        } catch (Exception e) {
        	System.err.print("Starting Group OSCORE applications: ");
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
        
        // Map<Short, CBORObject> params = new HashMap<>();
        // params.put(Constants.GRANT_TYPE, Token.clientCredentials);

        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);

        int myRoles = 0;
        myRoles = se.sics.ace.Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        myRoles = se.sics.ace.Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        cborArrayEntry.Add(myRoles);

        cborArrayScope.Add(cborArrayEntry);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
		
        /* Perform Token request */
        
        System.out.println("Performing Token request to AS.");
        System.out.println("AS Token resource is at: " + tokenURI);
        
		CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs2"),
                CBORObject.FromObject(byteStringScope), null);
        
        /*
         * OSCoreCtx ctx = new OSCoreCtx(key128, true, null, clientID.getBytes(Constants.charset),
         * "AS".getBytes(Constants.charset), null, null, null, null);
         */

        byte[] senderId = KeyStorage.aceSenderIds.get(clientID);
        byte[] recipientId = KeyStorage.aceSenderIds.get("AS");
        OSCoreCtx ctx = new OSCoreCtx(key128, true, null, senderId, recipientId,
                null, null, null, null);
        
        Response response = OSCOREProfileRequestsGroupOSCORE.getToken(
				tokenURI, params, ctx, db);
        
        System.out.println("DB content: " + db.getContext(new byte[] { 0x00 }, null));

        /* Parse and print response */
        
        System.out.println("Response from AS: " + response.getPayloadString());
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
        db.purge(); // FIXME: Remove?
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
	public static GroupCtx postTokenAndJoin(String memberName, String group, String publicPrivateKey,
			Response responseFromAS) throws IllegalStateException, InvalidCipherTextException, CoseException,
			AceException, OSException, ConnectorException, IOException {

        /* Configure parameters for the join request */

        boolean askForSignInfo = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;

        // Generate private and public key to be used in the OSCORE group by the joining client (EDDSA)
        InstallCryptoProviders.installProvider();
        String groupKeyPair = publicPrivateKey;// = InstallCryptoProviders.getCounterSignKey(); //"pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

        // Set EDDSA with curve Ed25519 for countersignatures
        int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();

//        // The cnf key used in these tests
//        byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
//
//        //The AS <-> RS key used in these tests
//        byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        
        String groupName = group; //"bbbbbb570000";
//        String audience = "rs2";
//        String asName = "AS";
//        String clientID = memberName; //"clientA";
//        String cti = "token4JoinMultipleRolesDeriv" + clientID;

        String gmBaseURI = "coap://" + GM_HOST + ":" + GM_PORT + "/";
        String authzInfoURI = gmBaseURI + "authz-info";
        String joinResourceURI = gmBaseURI + rootGroupMembershipResource + "/" + groupName;

        System.out.println("Performing Token post to GM followed by Join request.");
        System.out.println("GM join resource is at: " + joinResourceURI);

        /* Prepare ACE Token generated by the client */

//        //Generate a token (update to get Token from AS here instead)
//        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
//        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
//        Map<Short, CBORObject> params = new HashMap<>(); 
//
        //Create a byte string scope for use later
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);

        int myRoles = 0;
        myRoles = se.sics.ace.Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        myRoles = se.sics.ace.Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        cborArrayEntry.Add(myRoles);

        cborArrayScope.Add(cborArrayEntry);
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

        boolean askForEcdhInfo = true;
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(authzInfoURI, responseFromAS, askForSignInfo,
                askForEcdhInfo, db, usedRecipientIds);
        /* Check response from GM to Token post */

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(db.getContext(joinResourceURI));

        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());

        System.out.println("Receved response from GM to Token post: " + rsPayload.toString());

        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()

        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();

        @SuppressWarnings("unused")
        CBORObject signInfo = null;
        @SuppressWarnings("unused")
        CBORObject pubKeyEnc = null;

        if (askForSignInfo) {
            signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        }

        /* Now proceed to build join request to GM */

        CoapClient c = OSCOREProfileRequestsGroupOSCORE
                .getClient(new InetSocketAddress(joinResourceURI, GM_PORT),
                db);

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

        OSCoreCtx tmp = db.getContext(gmBaseURI);
        System.out.println("Client: Installing Security Context with Recipient ID: " + tmp.getRecipientIdString()
                + " Sender ID: " + tmp.getSenderIdString()
                + " ID Context: " + Utility.arrayToString(tmp.getIdContext()) + "\r\n");
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);

        /* Send to join request to GM */

        System.out.println("Performing Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);

        /* Parse response to Join request from GM */

        System.out.println("Response from GM to Join request: " + r2.getResponseText());
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

        CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

        //The following two lines are useful for generating the Group OSCORE context
		Map<Short, CBORObject> contextParams = new HashMap<>(
				GroupOSCOREInputMaterialObjectParameters.getParams(keyMap));
		GroupOSCOREInputMaterialObject contextObject = new GroupOSCOREInputMaterialObject(contextParams);

        System.out.println("Received response from GM to Join request: " + joinResponse.toString());

        /* Parse the Join response in detail */

        Util.printJoinResponse(joinResponse);
        
        if(!memberName.toLowerCase().contains("server1")) {
        	System.out.println("Has now joined the OSCORE group.");
        } else {
        	printPause(memberName, "Has now joined the OSCORE group.");
        }
        
        /* Generate a Group OSCORE security context from the Join response */

        CBORObject coseKeySetArray = CBORObject.NewArray();
        if(joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS))) {
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        }
        
		GroupCtx groupOscoreCtx = Util.generateGroupOSCOREContext(contextObject, coseKeySetArray, groupKeyPair);

        System.out.println();
        //System.out.println("Generated Group OSCORE Context:");
        Utility.printContextInfo(groupOscoreCtx);

        return groupOscoreCtx;
    }
    
    /**
     * Simple method for "press enter to continue" functionality
     */
    static void printPause(String memberName, String message) {
    	
    	//Only print for Server1
    	if(!memberName.toLowerCase().equals("server1")) {
    		return;
    	}
    	
    	System.out.println("===");
    	System.out.println(message);
    	System.out.println("Press ENTER to continue");
    	System.out.println("===");
        try {
            @SuppressWarnings("unused")
            int read = System.in.read(new byte[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
