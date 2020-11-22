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

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
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
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;

/**
 * A test case for the OSCORE profile interactions between client and server.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Hoeglund
 *
 */
public class TestOscorepClient2RSGroupOSCORE {

	private final String rootGroupMembershipResource = "ace-group";
	
    private static String groupKeyPair;
    private static String groupKeyPairUpdate;
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
    
    private static OSCoreCtxDB ctxDB;
    
	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
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
    	    
    	    // Alternative private and public key, for later uploading of a new public key (ECDSA_256)
    	    groupKeyPairUpdate = "pgMmAQIgASFYINhpLmzDRKUbuNYqt2jFLz0oExe3ifTxI2FIBtCwUUQ9IlggqfACRgS7AHxKkiEP71yoHHebxTA/jB5l8mhrgdIkQIgjWCCLF8p5CpN2Gy5v67a3/lbSEbZiPKna/Z80/uC/qu+WRA==";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (ECDSA_256)
    	    strPublicKeyPeer1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (ECDSA_256)
    	    strPublicKeyPeer2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    		
    	}

    	// EDDSA asymmetric keys
    	if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    	    groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
    	    
    	    // Alternative private and public key, for later uploading of a new public key (EDDSA - Ed25519)
    	    groupKeyPairUpdate = "pQMnAQEgBiFYICHJZEm981T2yDBrls/Z5ihZtRkOJ8D5JvvuoURgbbQEI1ggZsIlEzF3iOV8PFC2BGKoRi0K22HmCeYvC8xq1ui2C5c=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	    strPublicKeyPeer1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	    strPublicKeyPeer2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    		
    	}
    	
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    		
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
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost/authz-info", asRes, ctxDB, usedRecipientIds);
        
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
        Assert.assertNotNull(ctxDB.getContext(
        	     "coap://localhost/helloWorld"));
       
       //Submit a request

       CoapClient c = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost/temp", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
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
        
        //Create the scope        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        String groupName = new String("feedca570000");
        String nodeResourceLocationPath = "";
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinSingleRole".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForPubKeyEnc, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
        Assert.assertNotNull(ctxDB.getContext(
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
        	
        	if (csKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(csKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        // Prepare material for later tests
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
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

		        
        /////////////////
        //
        // Part 1
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000");

        requestPayload = CBORObject.NewMap();
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);

        myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayScope.Add(myRoles);
        
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayScope.Add(Constants.GROUP_OSCORE_REQUESTER);
        
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForPubKeys) {
           
            CBORObject getPubKeys = CBORObject.NewArray();
            getPubKeys.Add(CBORObject.NewArray()); // Ask the public keys for all possible roles
            
            // The following is required to retrieve the public keys of both the already present group members
            /*
            myRoles = 0;
            myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(0).Add(myRoles);            
            myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(0).Add(myRoles);
        	*/
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
           
        }
       
        if (providePublicKey) {
            
        	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
        	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
        	if (gm_sign_nonce == null)
        		Assert.fail("Error: the component N_S of the signature challence is null");
        	
            // For the time being, the client's public key can be only a COSE Key
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
            
            requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
            
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
            byte[] serializedCSignNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMSignNonceCBOR.length + serializedCSignNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
       	    offset += serializedGMSignNonceCBOR.length;
       	    System.arraycopy(serializedCSignNonceCBOR, 0, dataToSign, offset, serializedCSignNonceCBOR.length);
            
            // Old version, concatenating the plain bytes rather than the serialization of CBOR byte strings
            /*
       	    byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
       	    System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
       	    offset += byteStringScope.length;
       	    System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
       	    offset += gm_sign_nonce.length;
       	    System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	    */
       	    
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        // Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
       
        System.out.println("Received Join Reponse from the GM: " + CBORObject.DecodeFromBytes(r2.getPayload()).toString()); 
        
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	
        String nodeName =  Utils.bytesToHex(groupId) + "-" + Utils.bytesToHex(senderId);
        
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
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
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
                
        
        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Rquest using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000");
        
        Request keyDistrReq = new Request(Code.GET, Type.CON);
        keyDistrReq.getOptions().setOscore(new byte[0]);        
        
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        CoapResponse r3 = c.advanced(keyDistrReq);
       
        Assert.assertEquals("CONTENT", r3.getCode().name());
        
        responsePayload = r3.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        CoapClient c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r4 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/active");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        GroupStatusReq.getOptions().setOscore(new byte[0]);
        CoapResponse r5 = c1.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/policies");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c1.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key GET Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key GET request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        
        byte[] peerSenderId;
        OneKey peerPublicKey;
        byte[] peerSenderIdFromResponse;
        int expectedRoles = 0;
        
        Assert.assertEquals(3, coseKeySetArray.size());
       
        // Retrieve and check the public key of another node in the group
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
       
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
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
        
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = coseKeySetArray.get(2).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(2).get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the FETCH method
        
        System.out.println("Performing a Public Key FETCH Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject getPubKeys = CBORObject.NewArray();
        
        // Ask for the public keys of group members that are (also) both requester and responder
        // This will have a neutral effect, by matching only the node with Sender ID = 0x77
        getPubKeys.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        getPubKeys.get(0).Add(myRoles);
        

        // Ask for the public keys of the other group members
        getPubKeys.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getPubKeys.get(1).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getPubKeys.get(1).Add(peerSenderId);
        
        
        requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        
        PubKeyReq = new Request(Code.FETCH, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        PubKeyReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        
        Assert.assertEquals(2, coseKeySetArray.size());
        
        
        // Retrieve and check the public key of another node in the group
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
        
        
        // Retrieve and check the public key of another node in the group
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
        
        Assert.assertEquals(2, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        
        
        /////////////////
        //
        // Part 8
        //
        /////////////////
		
        // Send a Key Distribution Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Distribution Request GET Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyDistributionReq = new Request(Code.GET, Type.CON);
        KeyDistributionReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r9 = c1.advanced(KeyDistributionReq);

        System.out.println("");
        System.out.println("Sent Key Distribution GET request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r9.getCode().name());
        
        responsePayload = r9.getPayload();
        CBORObject KeyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.getType());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, KeyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        myMap = KeyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Renewal Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyRenewalReq = new Request(Code.PUT, Type.CON);
        KeyRenewalReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r10 = c1.advanced(KeyRenewalReq);

        System.out.println("");
        System.out.println("Sent Key Renewal Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r10.getCode().name());
        
        responsePayload = r10.getPayload();
        CBORObject KeyRenewalResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyRenewalResponse.getType());
        Assert.assertEquals(true, KeyRenewalResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_SENDER_ID)));
        Assert.assertEquals(CBORType.ByteString, KeyRenewalResponse.get(CBORObject.FromObject(Constants.GROUP_SENDER_ID)).getType());
     
        
        /////////////////
        //
        // Part 10
        //
        /////////////////
		
        // Send a Public Key Update Request to the node sub-resource /pub-key, using the POST method
        
        System.out.println("Performing a Public Key Update Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath + "/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath +  "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        requestPayload = CBORObject.NewMap();
        
        // For the time being, the client's public key can be only a COSE Key
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate))).PublicKey();

        requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());

        // Add the nonce for PoP of the Client's private key
        byte[] cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(Constants.CNONCE, cnonce);

        // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
        int offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate)))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
        byte[] serializedCSignNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
        byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMSignNonceCBOR.length + serializedCSignNonceCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
        offset += serializedGMSignNonceCBOR.length;
        System.arraycopy(serializedCSignNonceCBOR, 0, dataToSign, offset, serializedCSignNonceCBOR.length);

        byte[] clientSignature = computeSignature(privKey, dataToSign);

        if (clientSignature != null)
            requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        else
            Assert.fail("Computed signature is empty");
        
        Request PublicKeyUpdateReq = new Request(Code.POST, Type.CON);
        PublicKeyUpdateReq.getOptions().setOscore(new byte[0]);
        PublicKeyUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(PublicKeyUpdateReq);

        System.out.println("");
        System.out.println("Sent Public Key Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 12
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("Performing a Leaving Group Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r13 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r13.getCode().name());
        
        responsePayload = r13.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r14 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("UNAUTHORIZED", r14.getCode().name());
        
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
        
        // Create the scope
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        String groupName = new String("feedca570000");
        String nodeResourceLocationPath = "";
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // CBORObject cborArrayRoles = CBORObject.NewArray();
        // cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
        // cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
        // cborArrayEntry.Add(cborArrayRoles);
        
        cborArrayScope.Add(cborArrayEntry);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinMultipleRoles".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForPubKeyEnc, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
        Assert.assertNotNull(ctxDB.getContext(
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
        	
        	if (csKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(csKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        // Prepare material for later tests
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
					                  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
					                  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
					                  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
		final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
		                			  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
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
        
		
        /////////////////
        //
        // Part 1
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000");       
        requestPayload = CBORObject.NewMap();
       
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayRoles = CBORObject.NewArray();
        // cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
        // cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
        // cborArrayScope.Add(cborArrayRoles);
        
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForPubKeys) {
           
            CBORObject getPubKeys = CBORObject.NewArray();
            getPubKeys.Add(CBORObject.NewArray()); // Ask the public keys for all possible roles
            
            // The following is required to retrieve the public keys of both the already present group members
            /*
            myRoles = 0;
            myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(0).Add(myRoles);            
            myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(0).Add(myRoles);
        	*/
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
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
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
            byte[] serializedCSignNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMSignNonceCBOR.length + serializedCSignNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
       	    offset += serializedGMSignNonceCBOR.length;
       	    System.arraycopy(serializedCSignNonceCBOR, 0, dataToSign, offset, serializedCSignNonceCBOR.length);
            
            // Old version, concatenating the plain bytes rather than the serialization of CBOR byte strings
            /*
       	    byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
       	    System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
       	    offset += byteStringScope.length;
       	    System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
       	    offset += gm_sign_nonce.length;
       	    System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	    */
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
       
        // Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
       
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	String nodeName =  Utils.bytesToHex(groupId) + "-" + Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
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
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());

        
        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Rquest using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000");
        
        Request keyDistrReq = new Request(Code.GET, Type.CON);
        keyDistrReq.getOptions().setOscore(new byte[0]);
        
        
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        CoapResponse r3 = c.advanced(keyDistrReq);
       
        Assert.assertEquals("CONTENT", r3.getCode().name());
        
        responsePayload = r3.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        CoapClient c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r4 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/active");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        GroupStatusReq.getOptions().setOscore(new byte[0]);
        CoapResponse r5 = c1.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/policies");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c1.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());

        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key GET Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key GET request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        Assert.assertEquals(3, coseKeySetArray.size());
       
        byte[] peerSenderId;
        OneKey peerPublicKey;
        byte[] peerSenderIdFromResponse;
        
        // Retrieve and check the public key of another node in the group
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
       
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
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
        
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = coseKeySetArray.get(2).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(2).get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        int expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the FETCH method
        
        System.out.println("Performing a Public Key FETCH Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject getPubKeys = CBORObject.NewArray();
        
        // Ask for the public keys of group members that are (also) responder
        // This will match with both this node's public key, as well as the public key of the node with Sender ID 0x77 
        getPubKeys.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        getPubKeys.get(0).Add(myRoles);

        // Ask for the public keys of the other group members
        getPubKeys.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getPubKeys.get(1).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getPubKeys.get(1).Add(peerSenderId);
        
        
        requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        
        PubKeyReq = new Request(Code.FETCH, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        PubKeyReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        Assert.assertEquals(3, coseKeySetArray.size());
        
        
        // Retrieve and check the public key of another node in the group
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

        
        // Retrieve and check the public key this same node in the group
        peerSenderId = senderId;
        peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
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
        
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = coseKeySetArray.get(2).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(2).get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(2).get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(2).get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        
        
        /////////////////
        //
        // Part 8
        //
        /////////////////
		
        // Send a Key Distribution Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Distribution Request GET Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyDistributionReq = new Request(Code.GET, Type.CON);
        KeyDistributionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r9 = c1.advanced(KeyDistributionReq);
        
        System.out.println("");
        System.out.println("Sent Key Distribution GET request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r9.getCode().name());
        
        responsePayload = r9.getPayload();
        CBORObject KeyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.getType());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, KeyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        myMap = KeyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
       
       // EDDSA (Ed25519)
       if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
           Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
       }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(csAlg);
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Renewal Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyRenewalReq = new Request(Code.PUT, Type.CON);
        KeyRenewalReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r10 = c1.advanced(KeyRenewalReq);

        System.out.println("");
        System.out.println("Sent Key Renewal Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r10.getCode().name());
        
        responsePayload = r10.getPayload();
        CBORObject KeyRenewalResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyRenewalResponse.getType());
        Assert.assertEquals(true, KeyRenewalResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_SENDER_ID)));
        Assert.assertEquals(CBORType.ByteString, KeyRenewalResponse.get(CBORObject.FromObject(Constants.GROUP_SENDER_ID)).getType());
        
        
        
        /////////////////
        //
        // Part 10
        //
        /////////////////
		
        // Send a Public Key Update Request to the node sub-resource /pub-key, using the POST method
        
        System.out.println("Performing a Public Key Update Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath + "/pub-key");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath +  "/pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        requestPayload = CBORObject.NewMap();
        
        // For the time being, the client's public key can be only a COSE Key
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate))).PublicKey();

        requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());

        // Add the nonce for PoP of the Client's private key
        byte[] cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(Constants.CNONCE, cnonce);

        // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
        int offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate)))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
        byte[] serializedCSignNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
        byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMSignNonceCBOR.length + serializedCSignNonceCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
        offset += serializedGMSignNonceCBOR.length;
        System.arraycopy(serializedCSignNonceCBOR, 0, dataToSign, offset, serializedCSignNonceCBOR.length);

        byte[] clientSignature = computeSignature(privKey, dataToSign);

        if (clientSignature != null)
            requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        else
            Assert.fail("Computed signature is empty");
        
        Request PublicKeyUpdateReq = new Request(Code.POST, Type.CON);
        PublicKeyUpdateReq.getOptions().setOscore(new byte[0]);
        PublicKeyUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(PublicKeyUpdateReq);

        System.out.println("");
        System.out.println("Sent Public Key Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 12
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("Performing a Leaving Group Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r13 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r13.getCode().name());
        
        responsePayload = r13.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r14 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("UNAUTHORIZED", r14.getCode().name());
        
    }
    
    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {
        
        ctxDB.addContext("coap://localhost/helloWorld", osctx);
        CoapClient c = OSCOREProfileRequests.getClient(
                new InetSocketAddress(
                        "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
        
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
