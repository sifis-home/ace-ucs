/*******************************************************************************
 * Copyright (c) 2019, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.oscore.group;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.groscore.group.GroupRecipientCtx;
import org.eclipse.californium.groscore.group.GroupSenderCtx;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;
import se.sics.ace.rs.TokenRepository;

/**
 * A test case for the OSCORE profile interactions between client and server.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Hoeglund
 *
 */
public class TestOscorepClient2RSGroupOSCORE {

	private final String rootGroupMembershipResource = "group-oscore";
	
    private static String groupKeyPair;
    private static String strPublicKeyPeer1;
    private static String strPublicKeyPeer2;
	
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int countersignKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    /**
     * The cnf key used in these tests
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx osctx;
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            TestOscorepRSGroupOSCORE.stop();
        }
        
        @Override
        public void run() {
            try {
            	TestOscorepRSGroupOSCORE.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                	TestOscorepRSGroupOSCORE.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    @BeforeClass
    public static void setUp() throws OSException {
        srv = new RunTestServer();
        srv.run();
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnf, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null);
        
		// ECDSA asymmetric keys
    	if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (ECDSA_256)
    	    groupKeyPair = "piJYIBZKbV1Ll/VtH2ChKBHVXeegVeusYWTJ75MCy8v/Hwq+I1ggO+AEdZm0KqRLj4oPqI1NoRaXtY2fzE45RD6YQ78jBYYDJgECIVgg6Pmo1YUKUzzaJLn6ih7ik/ag4egeHlYKZP8TTWX37OwgAQ==";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (ECDSA_256)
    	    strPublicKeyPeer1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (ECDSA_256)
    	    strPublicKeyPeer2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    		
    	}

    	// EDDSA asymmetric keys
    	if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    	    groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	    strPublicKeyPeer1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	    strPublicKeyPeer2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    		
    	}
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception {

        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

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
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost/authz-info", asRes);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
       Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext(
               "coap://localhost/helloWorld"));
       
       //Submit a request
       CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT));
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       CoapClient c2 = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/temp", CoAP.DEFAULT_COAP_PORT));
       Request getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       CoapResponse getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       //Submit a request with unallowed method
       Request deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       CoapResponse deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(
               CoAP.ResponseCode.METHOD_NOT_ALLOWED));
       
    }
    
    // M.T.
    /**
     * Test post to Authz-Info, then join using a single role.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessGroupOSCORESingleRole() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;
        
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create a byte string scope for use later
        String groupName = new String("feedca570000");
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinSingleRole".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = "clientB".getBytes(Constants.charset); //Need different client ID
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, keyCnf);
        byte[] serverId = "rs2".getBytes(Constants.charset);
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
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForPubKeyEnc);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName));
        
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        CBORObject algCapabilitiesExpected = CBORObject.NewArray();
        CBORObject keyCapabilitiesExpected = CBORObject.NewArray();
        CBORObject csParamsExpected = null;
        CBORObject csKeyParamsExpected = null;
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	algCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.EC2_P256); // Curve
            csParamsExpected = CBORObject.NewArray();
            csKeyParamsExpected = CBORObject.NewArray();
            csParamsExpected.Add(algCapabilitiesExpected);
            csParamsExpected.Add(keyCapabilitiesExpected);
            csKeyParamsExpected = keyCapabilitiesExpected;
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	algCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.OKP_Ed25519); // Curve
            csParamsExpected = CBORObject.NewArray();
            csKeyParamsExpected = CBORObject.NewArray();
            csParamsExpected.Add(algCapabilitiesExpected);
            csParamsExpected.Add(keyCapabilitiesExpected);
            csKeyParamsExpected = keyCapabilitiesExpected;
        }
        
        CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (askForSignInfo) {
	    	
		    	if (csAlgExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csAlgExpected);
		    	if (csParamsExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csParamsExpected);
		    	if (csKeyParamsExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csKeyParamsExpected);

	    	}
	    	
	        if (askForPubKeyEnc) {
	        	
	        	if (csKeyEncExpected == null)
	        		signInfoEntry.Add(CBORObject.Null);
	        	else
	        		signInfoEntry.Add(csKeyEncExpected);
	        	
	        }
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        
        // Now proceed with the Join request
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT));
       
        System.out.println("Performing Join request using OSCORE to GM at " + "coap://localhost/feedca570000");
       
        CBORObject requestPayload = CBORObject.NewMap();
       
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        cborArrayScope.Add(Constants.GROUP_OSCORE_REQUESTER);
    	byteStringScope = cborArrayScope.EncodeToBytes();
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);
       
        // Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
       
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
       
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
        final byte[] senderId = new byte[] { (byte) 0x25 };
        final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
        final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
        final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
       
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
                
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
       
        CBORObject coseKeySetArray = null;
        if (askForPubKeys) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
           
            // The content of the byte string should be a COSE_KeySet, to be processed accordingly
           
            byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
            coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
            Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
            Assert.assertEquals(2, coseKeySetArray.size());
           
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
           
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = coseKeySetArray.get(0).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            // ECDSA_256
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            // ECDSA_256
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        }

    }
    
    // M.T.
    /**
     * Test post to Authz-Info, then join using multiple roles.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessGroupOSCOREMultipleRoles() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;
        
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create a byte string scope for use later
        String groupName = new String("feedca570000");
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);
        CBORObject cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
        cborArrayEntry.Add(cborArrayRoles);
        cborArrayScope.Add(cborArrayEntry);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinMultipleRoles".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = "clientC".getBytes(Constants.charset); //Need different client ID
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, keyCnf);
        byte[] serverId = "rs2".getBytes(Constants.charset);
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
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForPubKeyEnc);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext(
                "coap://localhost/feedca570000"));

        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        CBORObject algCapabilitiesExpected = CBORObject.NewArray();
        CBORObject keyCapabilitiesExpected = CBORObject.NewArray();
        CBORObject csParamsExpected = null;
        CBORObject csKeyParamsExpected = null;
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	algCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.EC2_P256); // Curve
            csParamsExpected = CBORObject.NewArray();
            csKeyParamsExpected = CBORObject.NewArray();
            csParamsExpected.Add(algCapabilitiesExpected);
            csParamsExpected.Add(keyCapabilitiesExpected);
            csKeyParamsExpected = keyCapabilitiesExpected;
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	algCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilitiesExpected.Add(KeyKeys.OKP_Ed25519); // Curve
            csParamsExpected = CBORObject.NewArray();
            csKeyParamsExpected = CBORObject.NewArray();
            csParamsExpected.Add(algCapabilitiesExpected);
            csParamsExpected.Add(keyCapabilitiesExpected);
            csKeyParamsExpected = keyCapabilitiesExpected;
        }
        
        CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (askForSignInfo) {
		    	
		    	if (csAlgExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csAlgExpected);
		    	if (csParamsExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csParamsExpected);
		    	if (csKeyParamsExpected == null)
		    		signInfoEntry.Add(CBORObject.Null);
		    	else
		    		signInfoEntry.Add(csKeyParamsExpected);

	    	}
	    	
	        if (askForPubKeyEnc) {
	        	
	        	if (csKeyEncExpected == null)
	        		signInfoEntry.Add(CBORObject.Null);
	        	else
	        		signInfoEntry.Add(csKeyEncExpected);
	        	
	        }
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        
        // Now proceed with the Join request        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT));
        
        System.out.println("Performing Join request using OSCORE to GM at " + "coap://localhost/feedca570000");
       
        CBORObject requestPayload = CBORObject.NewMap();
       
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
        cborArrayScope.Add(cborArrayRoles);
        byteStringScope = cborArrayScope.EncodeToBytes();
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);
       
        //Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
       
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
       
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
        final byte[] senderId = new byte[] { (byte) 0x25 };
        final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
        final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
        final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
       
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

        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
       
        CBORObject coseKeySetArray = null;
        if (askForPubKeys) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
           
            // The content of the byte string should be a COSE_KeySet, to be processed accordingly
           
            byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
            coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
            Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
            Assert.assertEquals(2, coseKeySetArray.size());
           
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
           
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = coseKeySetArray.get(0).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            // ECDSA_256
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            // ECDSA_256
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        }

    }
    
	// M.T. & Rikard
	/**
	 * Test post to Authz-Info, then join using multiple roles. Uses the ACE
	 * OSCORE Profile.
	 * 
	 * After the join a Group OSCORE context will be derived from the material
	 * received in the join response.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSuccessGroupOSCOREMultipleRolesContextDerivation() throws Exception {

		boolean askForSignInfo = true;
		boolean askForPubKeyEnc = true;
		boolean askForPubKeys = true;
		boolean providePublicKey = true;

		// Generate a token
		COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
		CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
		Map<Short, CBORObject> params = new HashMap<>();

		// Create a byte string scope for use later
		String groupName = new String("feedca570000");

		CBORObject cborArrayScope = CBORObject.NewArray();
		CBORObject cborArrayEntry = CBORObject.NewArray();
		cborArrayEntry.Add(groupName);
		CBORObject cborArrayRoles = CBORObject.NewArray();
		cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
		cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
		cborArrayEntry.Add(cborArrayRoles);
		cborArrayScope.Add(cborArrayEntry);
		byte[] byteStringScope = cborArrayScope.EncodeToBytes();

		params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
		params.put(Constants.AUD, CBORObject.FromObject("rs2"));
		params.put(Constants.CTI, CBORObject.FromObject("token4JoinMultipleRolesDerive".getBytes(Constants.charset))); // Need
																													// different
																													// CTI
		params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

		CBORObject osc = CBORObject.NewMap();
		byte[] clientId = "clientC".getBytes(Constants.charset); // Need
																	// different
																	// client ID
		osc.Add(Constants.OS_CLIENTID, clientId);
		osc.Add(Constants.OS_MS, keyCnf);
		byte[] serverId = "rs2".getBytes(Constants.charset);
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
		Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken("coap://localhost/authz-info", asRes,
				askForSignInfo, askForPubKeyEnc);
		assert (rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
		// Check that the OSCORE context has been created:
		Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext("coap://localhost/feedca570000"));

		CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
		// Sanity checks already occurred in
		// OSCOREProfileRequestsGroupOSCORE.postToken()

		// Nonce from the GM, to be signed together with a local nonce to prove
		// PoP of the private key
		byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();

		CBORObject signInfo = null;

		// Group OSCORE specific values for the countersignature
		CBORObject csAlgExpected = null;
		CBORObject algCapabilitiesExpected = CBORObject.NewArray();
		CBORObject keyCapabilitiesExpected = CBORObject.NewArray();
		CBORObject csParamsExpected = null;
		CBORObject csKeyParamsExpected = null;

		// ECDSA_256
		if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
			algCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
			keyCapabilitiesExpected.Add(KeyKeys.KeyType_EC2); // Key Type
			keyCapabilitiesExpected.Add(KeyKeys.EC2_P256); // Curve
			csParamsExpected = CBORObject.NewArray();
			csKeyParamsExpected = CBORObject.NewArray();
			csParamsExpected.Add(algCapabilitiesExpected);
			csParamsExpected.Add(keyCapabilitiesExpected);
			csKeyParamsExpected = keyCapabilitiesExpected;
		}

		// EDDSA (Ed25519)
		if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
			algCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
			keyCapabilitiesExpected.Add(KeyKeys.KeyType_OKP); // Key Type
			keyCapabilitiesExpected.Add(KeyKeys.OKP_Ed25519); // Curve
			csParamsExpected = CBORObject.NewArray();
			csKeyParamsExpected = CBORObject.NewArray();
			csParamsExpected.Add(algCapabilitiesExpected);
			csParamsExpected.Add(keyCapabilitiesExpected);
			csKeyParamsExpected = keyCapabilitiesExpected;
		}

		CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);

		if (askForSignInfo || askForPubKeyEnc) {
			Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
			Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
			signInfo = CBORObject.NewArray();
			signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));

			CBORObject signInfoExpected = CBORObject.NewArray();
			CBORObject signInfoEntry = CBORObject.NewArray();

			signInfoEntry.Add(CBORObject.FromObject(groupName));

			if (askForSignInfo) {

				if (csAlgExpected == null)
					signInfoEntry.Add(CBORObject.Null);
				else
					signInfoEntry.Add(csAlgExpected);
				if (csParamsExpected == null)
					signInfoEntry.Add(CBORObject.Null);
				else
					signInfoEntry.Add(csParamsExpected);
				if (csKeyParamsExpected == null)
					signInfoEntry.Add(CBORObject.Null);
				else
					signInfoEntry.Add(csKeyParamsExpected);

			}

			if (askForPubKeyEnc) {

				if (csKeyEncExpected == null)
					signInfoEntry.Add(CBORObject.Null);
				else
					signInfoEntry.Add(csKeyEncExpected);

			}

			signInfoExpected.Add(signInfoEntry);

			Assert.assertEquals(signInfo, signInfoExpected);
		}

		// Now proceed with the Join request
		CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT));

		System.out.println("Performing Join request using OSCORE to GM at " + "coap://localhost/feedca570000");

		CBORObject requestPayload = CBORObject.NewMap();

		cborArrayScope = CBORObject.NewArray();
		cborArrayScope.Add(groupName);
		cborArrayRoles = CBORObject.NewArray();
		cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
		cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
		cborArrayScope.Add(cborArrayRoles);
		byteStringScope = cborArrayScope.EncodeToBytes();
		requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));

		if (askForPubKeys) {

			CBORObject getPubKeys = CBORObject.NewArray();
			requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);

		}

		if (providePublicKey) {

			// For the time being, the client's public key can be only a COSE
			// Key
			OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))
					.PublicKey();

			requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());

			// Add the nonce for PoP of the Client's private key
			byte[] cnonce = new byte[8];
			new SecureRandom().nextBytes(cnonce);
			requestPayload.Add(Constants.CNONCE, cnonce);

			// Add the signature computed over (rsnonce | cnonce), using the
			// Client's private key
			PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))))
					.AsPrivateKey();
			byte[] dataToSign = new byte[gm_sign_nonce.length + cnonce.length];
			System.arraycopy(gm_sign_nonce, 0, dataToSign, 0, gm_sign_nonce.length);
			System.arraycopy(cnonce, 0, dataToSign, gm_sign_nonce.length, cnonce.length);

			byte[] clientSignature = computeSignature(privKey, dataToSign);

			if (clientSignature != null)
				requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
			else
				Assert.fail("Computed signature is empty");

		}

		Request joinReq = new Request(Code.POST, Type.CON);
		joinReq.getOptions().setOscore(new byte[0]);
		joinReq.setPayload(requestPayload.EncodeToBytes());
		joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);

		// Submit the request
		System.out.println("");
		System.out.println("Sent Join request to GM: " + requestPayload.toString());
		CoapResponse r2 = c.advanced(joinReq);

		Assert.assertEquals("CREATED", r2.getCode().name());

		byte[] responsePayload = r2.getPayload();
		CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

		Assert.assertEquals(CBORType.Map, joinResponse.getType());

		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
		Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
		// Assume that "Group_OSCORE_Security_Context object" is registered with
		// value 0 in the "ACE Groupcomm Key" Registry of
		// draft-ietf-ace-key-groupcomm
		Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());

		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
		Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());

		CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

		// Sanity check
		Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)));
		Assert.assertEquals(true,
				myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)));
		Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
		Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
		Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)));
		Assert.assertEquals(true,
				myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)));
		Assert.assertEquals(true,
				myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

		// ECDSA_256
		if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			Assert.assertEquals(true,
					myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
			Assert.assertEquals(true,
					myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
		}

		// EDDSA (Ed25519)
		if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			Assert.assertEquals(true,
					myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
			Assert.assertEquals(true,
					myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
		}

		// Check the presence, type and value of the signature key encoding
		Assert.assertEquals(true,
				myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
		Assert.assertEquals(CBORType.Integer,
				myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());
		Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY),
				myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));

		final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
				(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E,
				(byte) 0x0F, (byte) 0x10 };
		final byte[] masterSalt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23, (byte) 0x78,
				(byte) 0x63, (byte) 0x40 };
		final byte[] senderId = new byte[] { (byte) 0x25 };
		final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0,
				(byte) 0x5c };
		final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;

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

		Assert.assertArrayEquals(masterSecret,
				myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
		Assert.assertArrayEquals(senderId,
				myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());

		Assert.assertEquals(hkdf.AsCBOR(),
				myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
		Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
		Assert.assertArrayEquals(masterSalt,
				myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
		Assert.assertArrayEquals(groupId,
				myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
		Assert.assertNotNull(csAlg);
		Assert.assertEquals(csAlg.AsCBOR(),
				myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

		// Add default values for missing parameters
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
		if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
			myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));

		Map<Short, CBORObject> contextParams = new HashMap<>(
				OSCORESecurityContextObjectParameters.getParams(myMap));
		GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams);

		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
		Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
		// This assumes that the Group Manager did not rekeyed the group upon
		// previous nodes' joining
		Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());

		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
		Assert.assertEquals(CBORType.Integer,
				joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
		// Assume that "coap_group_oscore" is registered with value 0 in the
		// "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
		Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());

		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
		Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
		Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());

		if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
			Assert.assertEquals(CBORType.Array,
					myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
			Assert.assertEquals(CBORObject.FromObject(csParams),
					myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
		}

		if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
			Assert.assertEquals(CBORType.Array, myMap
					.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
			Assert.assertEquals(CBORObject.FromObject(csKeyParams),
					myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
		}

		CBORObject coseKeySetArray = null;
		if (askForPubKeys) {
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
			Assert.assertEquals(CBORType.ByteString,
					joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());

			// The content of the byte string should be a COSE_KeySet, to be
			// processed accordingly

			byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
			coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
			Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
			Assert.assertEquals(2, coseKeySetArray.size());

			byte[] peerSenderId;
			OneKey peerPublicKey;
			byte[] peerSenderIdFromResponse;

			peerSenderId = new byte[] { (byte) 0x52 };
			peerSenderIdFromResponse = coseKeySetArray.get(0).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
			peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
			Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);

			// ECDSA_256
			if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
				Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
				Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()),
						coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()),
						coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
			}

			// EDDSA (Ed25519)
			if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
				Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
				Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()),
						coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()),
						coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
			}

			peerSenderId = new byte[] { (byte) 0x77 };
			peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
			peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
			Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);

			// ECDSA_256
			if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
				Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
				Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()),
						coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()),
						coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
			}

			// EDDSA (Ed25519)
			if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
				Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
				Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()),
						coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
				Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()),
						coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
			}

		} else {
			Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
		}

		/* Group OSCORE Context derivation below */

		// Defining variables to hold the information before derivation

		// Algorithm
		AlgorithmID algo = null;
		CBORObject alg_param = contextObject.getParam(OSCORESecurityContextObjectParameters.alg);
		if (alg_param.getType() == CBORType.TextString) {
			algo = AlgorithmID.valueOf(alg_param.AsString());
		} else if (alg_param.getType() == CBORType.Integer) {
			algo = AlgorithmID.FromCBOR(alg_param);
		}

		// KDF
		AlgorithmID kdf = null;
		CBORObject kdf_param = contextObject.getParam(OSCORESecurityContextObjectParameters.hkdf);
		if (kdf_param.getType() == CBORType.TextString) {
			kdf = AlgorithmID.valueOf(kdf_param.AsString());
		} else if (kdf_param.getType() == CBORType.Integer) {
			kdf = AlgorithmID.FromCBOR(kdf_param);
		}

		// Algorithm for the countersignature
		AlgorithmID alg_countersign = null;
		CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
		if (alg_countersign_param.getType() == CBORType.TextString) {
			alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
		} else if (alg_countersign_param.getType() == CBORType.Integer) {
			alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
		}

		// Parameter for the par countersign parameter
		CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
		if (par_countersign_param.getType() != CBORType.Array) {
			System.err.println("Unknown par_countersign value!");
			Assert.fail();
		}
		// Parse the array
		Collection<CBORObject> par_countersign_collection = par_countersign_param.getValues();
		CBORObject[] outerArrayPar = par_countersign_collection
				.toArray(new CBORObject[par_countersign_collection.size()]);

		int[][] par_countersign = new int[outerArrayPar.length][];
		for (int i = 0; i < outerArrayPar.length; i++) {
			CBORObject innerArrayCbor = outerArrayPar[i];

			if (innerArrayCbor.getType() == CBORType.Array) {
				Collection<CBORObject> innerArrayCollection = innerArrayCbor.getValues();

				CBORObject[] innerArray = innerArrayCollection.toArray(new CBORObject[innerArrayCollection.size()]);

				par_countersign[i] = new int[innerArray.length];
				for (int n = 0; n < innerArray.length; n++) {
					par_countersign[i][n] = innerArray[n].AsInt32();
				}
			} else {
				par_countersign[i] = new int[1];
				par_countersign[i][0] = innerArrayCbor.AsInt32();
			}
		}

		// Parameter for the par countersign key parameter
		CBORObject par_countersign_key_param = contextObject
				.getParam(GroupOSCORESecurityContextObjectParameters.cs_key_params);
		if (par_countersign_key_param.getType() != CBORType.Array) {
			System.err.println("Unknown par_countersign_key value!");
			Assert.fail();
		}
		// Parse the array
		Collection<CBORObject> par_countersign_key_collection = par_countersign_key_param.getValues();
		CBORObject[] arrayKey = par_countersign_key_collection
				.toArray(new CBORObject[par_countersign_key_collection.size()]);

		int[] par_countersign_key = new int[arrayKey.length];
		for (int i = 0; i < arrayKey.length; i++) {
			par_countersign_key[i] = arrayKey[i].AsInt32();
		}
		
		// Master secret
		CBORObject master_secret_param = contextObject.getParam(OSCORESecurityContextObjectParameters.ms);
		byte[] master_secret = null;
		if (master_secret_param.getType() == CBORType.ByteString) {
			master_secret = master_secret_param.GetByteString();
		}

		// Master salt
		CBORObject master_salt_param = contextObject.getParam(OSCORESecurityContextObjectParameters.salt);
		byte[] master_salt = null;
		if (master_salt_param.getType() == CBORType.ByteString) {
			master_salt = master_salt_param.GetByteString();
		}

		// Sender ID
		byte[] sid = null;
		CBORObject sid_param = contextObject.getParam(OSCORESecurityContextObjectParameters.clientId);
		if (sid_param.getType() == CBORType.ByteString) {
			sid = sid_param.GetByteString();
		}

		// Group ID / Context ID
		CBORObject group_identifier_param = contextObject
				.getParam(OSCORESecurityContextObjectParameters.contextId);
		byte[] group_identifier = null;
		if (group_identifier_param.getType() == CBORType.ByteString) {
			group_identifier = group_identifier_param.GetByteString();
		}

		// RPL (replay window information)
		int rpl = 32; // Default value

		// Check that all values were received
		assertNotNull(group_identifier);
		assertNotNull(sid);
		assertNotNull(algo);
		assertNotNull(master_salt);
		assertNotNull(master_secret);
		assertNotNull(par_countersign);
		assertNotNull(par_countersign_key);
		assertNotNull(rpl);
		assertNotNull(kdf);
		assertNotNull(alg_countersign);

		// Converts AlgorithmID parameters to those from Cose in Californium
		int algInt = algo.AsCBOR().AsInt32();
		CBORObject algCbor = CBORObject.FromObject(algInt);
		org.eclipse.californium.grcose.AlgorithmID algCose = null;
		try {
			algCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(algCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		int hkdfInt = kdf.AsCBOR().AsInt32();
		CBORObject hkdfCbor = CBORObject.FromObject(hkdfInt);
		org.eclipse.californium.grcose.AlgorithmID hkdfCose = null;
		try {
			hkdfCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(hkdfCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		int algCsInt = alg_countersign.AsCBOR().AsInt32();
		CBORObject algCsCbor = CBORObject.FromObject(algCsInt);
		org.eclipse.californium.grcose.AlgorithmID algCsCose = null;
		try {
			algCsCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(algCsCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Derive the Group OSCORE context
		org.eclipse.californium.groscore.group.GroupCtx groupCtx = new org.eclipse.californium.groscore.group.GroupCtx(
				master_secret, master_salt, algCose, hkdfCose, group_identifier, algCsCose, par_countersign,
				par_countersign_key);

		// Set up private & public keys for sender (not from response but set by
		// client)
		String sid_private_key_string = groupKeyPair;
		org.eclipse.californium.grcose.OneKey senderFullKey = new org.eclipse.californium.grcose.OneKey(
				CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));

		// Add the sender context
		groupCtx.addSenderCtx(sid, senderFullKey);

		// Add the recipient contexts from the coseKeySetArray
		byte[] rid = null;
		for (int i = 0; i < coseKeySetArray.size(); i++) {

			CBORObject key_param = coseKeySetArray.get(i);

			rid = null;
			CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
			if (rid_param.getType() == CBORType.ByteString) {
				rid = rid_param.GetByteString();
			}

			org.eclipse.californium.grcose.OneKey recipientPublicKey = new org.eclipse.californium.grcose.OneKey(
					key_param);
			groupCtx.addRecipientCtx(rid, rpl, recipientPublicKey);
		}

		// Check some parameters on the created sender and recipient contexts
		org.eclipse.californium.groscore.HashMapCtxDB db = new org.eclipse.californium.groscore.HashMapCtxDB();
		db.addContext("localhost", groupCtx);

		// Check sender context
		org.eclipse.californium.groscore.group.GroupSenderCtx senderCtx = (GroupSenderCtx) db.getContext("localhost");
		assertTrue(senderCtx.getPrivateKey().equals(senderFullKey));
		assertArrayEquals(senderCtx.getParCountersignKey(), par_countersign_key);
		assertArrayEquals(new byte[] { (byte) 0x25 }, senderCtx.getSenderId());

		// Check one recipient context
		org.eclipse.californium.groscore.group.GroupRecipientCtx recipientCtx = (GroupRecipientCtx) db.getContext(rid,
				group_identifier);
		assertArrayEquals(master_secret, recipientCtx.getMasterSecret());
		assertArrayEquals(recipientCtx.getParCountersignKey(), par_countersign_key);
		assertArrayEquals(new byte[] { (byte) 0x77 }, recipientCtx.getRecipientId());
	}

    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {

        OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
        db.addContext("coap://localhost/helloWorld", osctx);
        CoapClient c = OSCOREProfileRequests.getClient(
                new InetSocketAddress(
                        "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT));
        CoapResponse res = c.get();
        assert(res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED));
    }
    
    
    /**
     * Compute a signature, using the same algorithm and private key used in the OSCORE group to join
     * 
     * @param privKey  private key used to sign
     * @param dataToSign  content to sign
     * @return The computed signature
     
     */
    public byte[] computeSignature(PrivateKey privKey, byte[] dataToSign) {

        Signature mySignature = null;
        byte[] clientSignature = null;

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
                mySignature.initSign(privKey);
            else
                Assert.fail("Signature algorithm has not been initialized");
        }
        catch (InvalidKeyException e) {
            System.out.println(e.getMessage());
            Assert.fail("Invalid key excpetion - Invalid private key");
        }
        
        try {
        	if (mySignature != null) {
	            mySignature.update(dataToSign);
	            clientSignature = mySignature.sign();
        	}
        } catch (SignatureException e) {
            System.out.println(e.getMessage());
            Assert.fail("Failed signature computation");
        }
        
        return clientSignature;
        
    }

}
