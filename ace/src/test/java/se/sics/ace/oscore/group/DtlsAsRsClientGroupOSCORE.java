package se.sics.ace.oscore.group;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.postgresql.core.Utils;

import com.upokecenter.cbor.CBORObject;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

/**
 * 
 * FIXME: Needs updating after import of master code
 * 
 * Note: May be out of date considering recent changes.
 * 
 * Client application that requests and receives a token from the AS.
 * 
 * This Token is then posted to the RS (Group Manager) followed by sending of
 * the Join request and generating a Group OSCORE context from the reply.
 * 
 * To be ran together with CoapASTestServerGroupOSCORE & TestDtlspRSGroupOSCORE
 * (Be careful to set the ports so they do not overlap.)
 * 
 * Work in progress. Currently fails with "Unsupported key wrap algorithm in
 * token: null" from AS
 * 
 * @author Rikard Höglund
 */
public class DtlsAsRsClientGroupOSCORE {

	//Sets the AS secure port to use
	private final static int AS_SECURE_PORT = CoAP.DEFAULT_COAP_SECURE_PORT + 100;
	//Set the hostname/IP of the AS
	private final static String AS_ADDRESS = "localhost";
	
	//Sets the GM secure port to use
	private final static int GM_SECURE_PORT = CoAP.DEFAULT_COAP_SECURE_PORT;
	//Sets the GM insecure port to use
	private final static int GM_PORT = CoAP.DEFAULT_COAP_PORT;
	//Set the hostname/IP of the RS (GM)
	private final static String GM_ADDRESS = "localhost";

	/**
	 * Main method that executes the Token request and Token post.
	 * 
	 * @param args
	 * @throws Exception
	 */
    public static void main(String[] args) throws Exception {
    	
    	//Install needed cryptography providers
		Provider PROVIDER = new BouncyCastleProvider();
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(PROVIDER, 1);
		Security.insertProviderAt(EdDSA, 0);
     
    	//Perform token request to AS using PSK
    	CBORObject asResponse = groupOSCOREMultipleRolesCWT();
    	System.out.println("Received Response from AS: " + asResponse.toString());	
    	//Perform token request to AS using RPK
    	//CBORObject asResponse = groupOSCOREMultipleRolesCWT_RPK();
    	
    	//Send token and perform joining request to GM
    	System.out.println("Sending Token to GM followed by Join request: ");	
    	postPSKGroupOSCOREMultipleRolesContextDerivation(asResponse);
    	
    	//Cleans up after the execution
    	new File(TestConfig.testFilePath + "tokens.json").delete();	
    }
	
	// M.T.
    /**
	 * Request a CoapToken using PSK, for asking access to an OSCORE group with
	 * multiple roles, using a CWT.
	 * 
	 * @return the received Token
	 * 
	 * @throws IOException if communication fails
	 * @throws ConnectorException if communication fails
	 * @throws AceException if ACE processing fails
	 * 
	 */
    public static CBORObject groupOSCOREMultipleRolesCWT() throws IOException, ConnectorException, AceException { 

    	//Key information
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
   	
    	String tokenURI = "coaps://" + AS_ADDRESS + ":" + AS_SECURE_PORT + "/token";

    	System.out.println("Performing Token request to AS at " + tokenURI);
    	System.out.println("Using PSK DTLS towards AS");
    	
    	String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("monitor");
    	
    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientF", key128));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(tokenURI);
        client.setEndpoint(e);
        dtlsConnector.start();
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // Both requested roles are allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs4"));
        
		CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
		
        CBORObject responseFromAS = CBORObject.DecodeFromBytes(response.getPayload());
        
        
        Map<Short, CBORObject> map = Constants.getParams(responseFromAS);
        
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        System.out.println("Received reply from AS: " + responseFromAS.ToJSONString());
        System.out.println("Access Token: " + map.get(Constants.ACCESS_TOKEN).ToJSONString());
        System.out.println("Cnf: " + map.get(Constants.CNF).ToJSONString());
        
        //Returns the full response from the AS (a CBORObject map)
        //CBORObject token = CBORObject.DecodeFromBytes(map.get(Constants.ACCESS_TOKEN).GetByteString());
        //return map.get(Constants.ACCESS_TOKEN);
        return responseFromAS;
     }
    
    // M.T.
    /**
	 * Request a CoapToken using RPK, for asking access to an OSCORE group with
	 * multiple roles, using a CWT.
	 * 
	 * @return the received Token
	 * 
	 * @throws IOException if communication fails
	 * @throws ConnectorException if communication fails
	 * @throws AceException if ACE processing fails
	 * @throws CoseException if COSE processing fails
	 * 
	 */
    public static CBORObject groupOSCOREMultipleRolesCWT_RPK() throws IOException, ConnectorException, AceException, CoseException { 

    	//Rikard: Name that clientF will have getSenderId() in Token when using RPK:
        // ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w

    	//Key information
        String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    	
    	String tokenURI = "coaps://" + AS_ADDRESS + ":" + AS_SECURE_PORT + "/token";

    	System.out.println("Performing Token request to AS at " + tokenURI);
    	System.out.println("Using RPK DTLS towards AS");
    	
    	String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("monitor");
    	
    	//RPK connecting code from TestDtlsClient2
    	OneKey key = new OneKey(
                CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));

        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setIdentity(key.AsPrivateKey(), 
                key.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setRpkTrustAll();
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(tokenURI);
        client.setEndpoint(e);
        dtlsConnector.start();
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // Both requested roles are allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs4"));
        
		CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
		
        CBORObject responseFromAS = CBORObject.DecodeFromBytes(response.getPayload());
        
        
        Map<Short, CBORObject> map = Constants.getParams(responseFromAS);
        
        
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        System.out.println("Received reply from AS: " + responseFromAS.ToJSONString());
        System.out.println("Access Token: " + map.get(Constants.ACCESS_TOKEN).ToJSONString());
        System.out.println("Cnf: " + map.get(Constants.CNF).ToJSONString());
        
        //Returns the token
        CBORObject token = CBORObject.DecodeFromBytes(map.get(Constants.ACCESS_TOKEN).GetByteString());
        //return map.get(Constants.ACCESS_TOKEN);
        return token;
     }
    
    // M.T. & Rikard
    /**
	 * Post Token to authz-info with PSK then request for joining an OSCORE
	 * Group with multiple roles. This will then be followed by derivation of a
	 * Group OSCORE context based on the information received from the GM.
	 * 
	 * @param asResponse the response from the AS to the Token post
	 * 
	 * @throws CoseException if COSE key generation fails
	 * @throws AceException if ACE processing fails
	 * @throws InvalidCipherTextException if using an invalid cipher
	 * @throws IllegalStateException on failure
	 * @throws IOException for communication failures
	 * @throws ConnectorException for communication failures
	 * 
	 */
    public static void postPSKGroupOSCOREMultipleRolesContextDerivation(CBORObject asResponse) throws CoseException, IllegalStateException, InvalidCipherTextException, AceException, ConnectorException, IOException {
    	
    	//First parse the response from the AS
    	CBORObject tokenToPost = null;
		// CBORObject tokenToPost2 = null;
    	OneKey cnfKey = null;
    	CBORObject cnfFromAS = null;
    	if(asResponse != null) {
    		Map<Short, CBORObject> map = Constants.getParams(asResponse);
    		
    		//tokenToPost = map.get(Constants.ACCESS_TOKEN);
    		tokenToPost = CBORObject.DecodeFromBytes(map.get(Constants.ACCESS_TOKEN).GetByteString());

    		cnfFromAS = map.get(Constants.CNF);
    		
    		Map<Short, CBORObject> cnfMap = Constants.getParams(cnfFromAS);
    	
    		cnfKey = new OneKey(cnfMap.get(Constants.COSE_KEY));
    	}
    	
    	//Set some parameters
    	byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    	byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
	    // Private and public key to be used in the OSCORE group (EDDSA)
	    String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
	
	    String rsAddrC;
	    String rsGroupRes;
	    String zeroEpochGroupID;
	    
	    CwtCryptoCtx ctx;
	    
	    rsAddrC = "coap://" + GM_ADDRESS + ":" + GM_PORT + "/authz-info";
	
	    zeroEpochGroupID = "feedca570000";
	    rsGroupRes = "coaps://" + GM_ADDRESS + ":" + GM_SECURE_PORT + "/" + zeroEpochGroupID;
	    
	    COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
	            AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
	    ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
    	
    	OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourPSK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
               
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
        CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostPSKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        //If a Token was provided to this method, post it.
        //Otherwise generate own token.
        CWT token;
        CBORObject payload;
        if(tokenToPost != null) {
        	payload = tokenToPost;
        } else {
        	token = new CWT(params);
        	payload = token.encode(ctx);
        }
        //If the PSK Identity and PSK has been set earlier during the Token request to the AS use them
        byte[] kidBytes = null;
        if (cnfKey != null) {
        	kidBytes = cnfKey.get(KeyKeys.KeyId).GetByteString();
        	key = cnfKey;
        } else {
        	kidBytes = kidStr.getBytes(Constants.charset);
        	System.out.println("cnfKey is null!");
        }

        //System.out.println("Key string: " + cnfKey.toString());
		System.out.println("Key ID bytes: " + Utils.toHexString((cnfKey.get(KeyKeys.KeyId).GetByteString())));
        System.out.println("Octet bytes: " + Utils.toHexString(cnfKey.get(KeyKeys.Octet_K).GetByteString()));
        System.out.println("CNF: " + cnfFromAS.ToJSONString());
        
        System.out.println("Posting Token to GM at " + rsAddrC);
        System.out.println("Using Token: " + payload.ToJSONString());
        
        @SuppressWarnings("unused")
		CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        
        //Prepare for join request
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidBytes,
                key);
        System.out.println("Performing Join request to GM at " + rsGroupRes);
        c.setURI(rsGroupRes);
        
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
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Add default values for missing parameters
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
		Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
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
        
		// Add checking of the derived context
		GroupOSCOREUtils.groupOSCOREContextDeriver(joinResponse, groupKeyPair);
		
		
    }
    
    
	
}
