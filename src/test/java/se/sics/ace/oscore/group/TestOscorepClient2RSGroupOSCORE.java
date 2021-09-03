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
import java.security.PublicKey;
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
 * @author Marco Tiloca and Rikard Hoeglund
 *
 */
public class TestOscorepClient2RSGroupOSCORE {

	private final String rootGroupMembershipResource = "ace-group";
	
    private static String groupKeyPair;
    private static String groupKeyPairUpdate;
    private static String strPublicKeyPeer1;
    private static String strPublicKeyPeer2;
	private static String gmPublicKeyStr;
	
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set curve X25519 for pairwise key derivation
    private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();

    
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
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (ECDSA_256)
    	    groupKeyPair = "piJYIBZKbV1Ll/VtH2ChKBHVXeegVeusYWTJ75MCy8v/Hwq+I1ggO+AEdZm0KqRLj4oPqI1NoRaXtY2fzE45RD6YQ78jBYYDJgECIVgg6Pmo1YUKUzzaJLn6ih7ik/ag4egeHlYKZP8TTWX37OwgAQ==";
    	    
    	    // Alternative private and public key, for later uploading of a new public key (ECDSA_256)
    	    groupKeyPairUpdate = "pgMmAQIgASFYINhpLmzDRKUbuNYqt2jFLz0oExe3ifTxI2FIBtCwUUQ9IlggqfACRgS7AHxKkiEP71yoHHebxTA/jB5l8mhrgdIkQIgjWCCLF8p5CpN2Gy5v67a3/lbSEbZiPKna/Z80/uC/qu+WRA==";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (ECDSA_256)
    	    strPublicKeyPeer1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (ECDSA_256)
    	    strPublicKeyPeer2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    		
    	    // Public key of the Group Manager (ECDSA_256)
    	    gmPublicKeyStr = "pQMmAQIgASFYICI2ZYymdbti17JGI9sEU6O5BTO3w7IhzBwsc8TpGdVAIlggdwkWvEyXw8RmBPQwsGFwx7PWBiYzdWYowxGA+ju2Whs=";
    	}

    	// EDDSA asymmetric keys
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    	    groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
    	    
    	    // Alternative private and public key, for later uploading of a new public key (EDDSA - Ed25519)
    	    groupKeyPairUpdate = "pQMnAQEgBiFYICHJZEm981T2yDBrls/Z5ihZtRkOJ8D5JvvuoURgbbQEI1ggZsIlEzF3iOV8PFC2BGKoRi0K22HmCeYvC8xq1ui2C5c=";
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	    strPublicKeyPeer1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	    strPublicKeyPeer2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    		
    	    // Public key of the Group Manager (EDDSA - Ed25519)
    	    gmPublicKeyStr = "pAMnAQEgBiFYIMbsZl6Be9BkNA58JLuToR6OwHNc5IeQ+cRY9/o0C4yj";
    	    
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
    

    /**
     * Test post to Authz-Info, then join using a single role.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessGroupOSCORESingleRole() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
        
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
                "coap://localhost/authz-info", asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName));
        
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        byte[] gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
                // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
                // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();
        
        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS);
        
        
        if (askForSignInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfoExpected, signInfo);
        }
        
        if (askForEcdhInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
        	
        	if (rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
        	
	            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
	            ecdhInfo = CBORObject.NewArray();
	        	ecdhInfo = rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO));
	        	
		    	CBORObject ecdhInfoExpected = CBORObject.NewArray();
		    	CBORObject ecdhInfoEntry = CBORObject.NewArray();
		    	
		    	ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		    	
		    	if (ecdhAlgExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhAlgExpected);
		    	
		    	if (ecdhParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhParamsExpected);
		    	
		    	if (ecdhKeyParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhKeyParamsExpected);
	        	
	        	if (pubKeyEncExpected == null)
	        		ecdhInfoEntry.Add(CBORObject.Null);
	        	else
	        		ecdhInfoEntry.Add(pubKeyEncExpected);
		    	
	        	ecdhInfoExpected.Add(ecdhInfoEntry);
	
	        	Assert.assertEquals(ecdhInfoExpected, ecdhInfo);
	        	
        	}
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

		final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
			

		

		
		final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID signAlg = null;
		CBORObject signAlgCapabilities = CBORObject.NewArray();
		CBORObject signKeyCapabilities = CBORObject.NewArray();
		CBORObject signParams = CBORObject.NewArray();
		
		// ECDSA_256
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		signAlg = AlgorithmID.ECDSA_256;
		signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
		}
			
		// EDDSA (Ed25519)
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		signAlg = AlgorithmID.EDDSA;
		signAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
		}
			
		signParams.Add(signAlgCapabilities);
		signParams.Add(signKeyCapabilities);
		
		
		final AlgorithmID ecdhAlg = AlgorithmID.ECDH_SS_HKDF_256;
		CBORObject ecdhAlgCapabilities = CBORObject.NewArray();
		CBORObject ecdhKeyCapabilities = CBORObject.NewArray();
		CBORObject ecdhParams = CBORObject.NewArray();
		
		// ECDSA_256
		if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
		}
			
		// X25519
		if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519); // Curve
		}
			
		ecdhParams.Add(ecdhAlgCapabilities);
		ecdhParams.Add(ecdhKeyCapabilities);

		        
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayScope.Add(myRoles);
        
        
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForPubKeys) {
           
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
           
        }
       
        if (providePublicKey) {
            
        	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
        	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
        	if (gm_nonce == null)
        		Assert.fail("Error: the component N_S of the PoP evidence challence is null");
        	
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
            
            CBORObject encodedPublicKey = null;
            switch (pubKeyEncExpected.AsInt32()) {
            	case Constants.COSE_HEADER_PARAM_UCCS:
            		// Build a UCCS including the public key
            		encodedPublicKey = Util.oneKeyToUccs(publicKey, "");
            		break;
            	case Constants.COSE_HEADER_PARAM_CWT:
        			// Build a CWT including the public key
        			// TODO
            		break;
            	case Constants.COSE_HEADER_PARAM_X5CHAIN:
            		// Build/retrieve the certificate including the public key
            		// TODO
            		break;
            }
        	requestPayload.Add(Constants.CLIENT_CRED, encodedPublicKey);
            
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
            
       	    
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        
        int pubKeyEnc = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).AsInt32();
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
        
        CBORObject pubKeysArray = null;
        
        if (askForPubKeys) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
           
            pubKeysArray = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS));
            Assert.assertEquals(2, pubKeysArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerPublicKeyRetrievedEncoded;
            byte[] peerSenderIdFromResponse;
            
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
 				   get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
            peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
            switch (pubKeyEnc) {
	            case Constants.COSE_HEADER_PARAM_UCCS:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
	                	// Retrieve the public key from the UCCS
	                	peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                	// TODO
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
	            		// TODO
	            	}
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            default:
	            	Assert.fail("Invalid format of public key");
            }
            if (peerPublicKeyRetrieved == null)
            	Assert.fail("Invalid format of public key");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
            
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = joinResponse.
 				   get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
            switch (pubKeyEnc) {
	            case Constants.COSE_HEADER_PARAM_UCCS:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
	                	// Retrieve the public key from the UCCS
	                	peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	                
	            case Constants.COSE_HEADER_PARAM_CWT:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                	// TODO
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	                
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
	            		// TODO
	            	}
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            default:
	                Assert.fail("Invalid format of public key");
	        }
            if (peerPublicKeyRetrieved == null)
            	Assert.fail("Invalid format of public key");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
            
            
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
            
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        
		// Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
 
        OneKey gmPublicKeyRetrieved = null;
        CBORObject gmPublicKeyRetrievedEncoded = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                	// Retrieve the public key from the UCCS
                    gmPublicKeyRetrieved = Util.uccsToOneKey(gmPublicKeyRetrievedEncoded);
                }
                else {
                	Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                	// TODO
                }
                else {
                	Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            default:
            	Assert.fail("Invalid format of Group Manager public key");
        }
        if (gmPublicKeyRetrieved == null)
        	Assert.fail("Invalid format of Group Manager public key");
        Assert.assertEquals(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)),
        					gmPublicKeyRetrieved.AsCBOR());
        
		byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
		
    	CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
    	byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
        
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence));

    	
        
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
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
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        pubKeysArray = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS));
        Assert.assertEquals(3, pubKeysArray.size());
        
        byte[] peerSenderId;
        OneKey peerPublicKey;
        OneKey peerPublicKeyRetrieved = null;
        CBORObject peerPublicKeyRetrievedEncoded;
        byte[] peerSenderIdFromResponse;
        int expectedRoles = 0;
               
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                	// Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                	// Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(2).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(2);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map)
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                else if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
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
        
        // Ask for the public keys of group members that are (also) both requester and responder
        // This will have a neutral effect, by matching only the node with Sender ID = 0x77
        
        getPubKeys.Add(CBORObject.True);
        
        getPubKeys.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        getPubKeys.get(1).Add(myRoles);
        

        // Ask for the public keys of the other group members
        getPubKeys.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getPubKeys.get(2).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getPubKeys.get(2).Add(peerSenderId);
        
        requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        
        PubKeyReq = new Request(Code.FETCH, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        PubKeyReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        PubKeyReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        pubKeysArray = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS));
        Assert.assertEquals(2, pubKeysArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(2, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                	// Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
                
        Assert.assertEquals(2, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());

        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
        
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }

        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the PUT method
        
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
        
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate))).PublicKey();

        CBORObject encodedPublicKey = null;
        switch (pubKeyEncExpected.AsInt32()) {
            case Constants.COSE_HEADER_PARAM_UCCS:
            	// Build a UCCS including the public key
                encodedPublicKey = Util.oneKeyToUccs(publicKey, "");
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                // Build/retrieve a CWT including the public key
                // TODO
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Build/retrieve the certificate including the public key
                // TODO
                break;
        }
        requestPayload.Add(Constants.CLIENT_CRED, encodedPublicKey);

        // Add the nonce for PoP of the Client's private key
        byte[] cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(Constants.CNONCE, cnonce);

        // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
        int offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate)))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
        byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
        byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
        offset += serializedGMNonceCBOR.length;
        System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);

        byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);

        if (clientSignature != null)
            requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        else
            Assert.fail("Computed signature is empty");
        
        Request PublicKeyUpdateReq = new Request(Code.POST, Type.CON);
        PublicKeyUpdateReq.getOptions().setOscore(new byte[0]);
        PublicKeyUpdateReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        PublicKeyUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(PublicKeyUpdateReq);

        System.out.println("");
        System.out.println("Sent Public Key Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 11
        //
        /////////////////
		
        // Send a Group Name and URI Retrieval Request, using the FETCH method
        
        System.out.println("Performing a Group Name and URI Retrieval Request using OSCORE to GM at " + "coap://localhost/ace-group");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource, CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject reqGroupIds = CBORObject.NewArray();
        reqGroupIds.Add(CBORObject.FromObject(groupId));
        
        requestPayload.Add(Constants.GID, reqGroupIds);
        
        Request GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r12 = c1.advanced(GroupNamesReq);
        
        System.out.println("");
        System.out.println("Sent Group Name and URI Retrieval Request FETCH request to GM");

        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(3, myObject.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GID)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GNAME)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GURI)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GID)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GNAME)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GURI)).getType());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GID)).size());
        Assert.assertArrayEquals(groupId, myObject.get(CBORObject.FromObject(Constants.GID)).get(0).GetByteString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GNAME)).size());
        Assert.assertEquals(groupName, myObject.get(CBORObject.FromObject(Constants.GNAME)).get(0).AsString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GURI)).size());
        String expectedUri = new String("/" + rootGroupMembershipResource + "/" + groupName);
        Assert.assertEquals(expectedUri, myObject.get(CBORObject.FromObject(Constants.GURI)).get(0).AsString());
        
        // Send a second request, indicating the Group ID of a non existing OSCORE group
        
        requestPayload = CBORObject.NewMap();

        reqGroupIds = CBORObject.NewArray();
        byte[] groupId2 = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22 };
        reqGroupIds.Add(CBORObject.FromObject(groupId2));
        
        requestPayload.Add(Constants.GID, reqGroupIds);
        
        GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        r12 = c1.advanced(GroupNamesReq);
        
        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.ByteString, myObject.getType());
        Assert.assertEquals(0, myObject.size());
        

        /////////////////
        //
        // Part 12
        //
        /////////////////
        
        // Send a Group Manager Public Key Request, using the GET method

        System.out.println("Performing a Group Manager Public Key GET Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/gm-pub-key");

        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/gm-pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GmPubKeyReq = new Request(Code.GET, Type.CON);
        GmPubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r13 = c1.advanced(GmPubKeyReq);

        System.out.println("");
        System.out.println("Sent Group Manager Public Key GET request to GM");

        Assert.assertEquals("CONTENT", r13.getCode().name());

        myObject = CBORObject.DecodeFromBytes(r13.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        
        gmPublicKeyRetrieved = null;
        gmPublicKeyRetrievedEncoded = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    gmPublicKeyRetrieved = Util.uccsToOneKey(gmPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
            	if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            default:
                Assert.fail("Invalid format of Group Manager public key");
        }
        if (gmPublicKeyRetrieved == null)
            Assert.fail("Invalid format of Group Manager public key");
        Assert.assertEquals(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)),
                            gmPublicKeyRetrieved.AsCBOR());
        
		gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
		
    	gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
    	rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
    	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence));
        
        
        
        
        
        /////////////////
        //
        // Part 13
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("Performing a Leaving Group Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r14 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r14.getCode().name());
        
        responsePayload = r14.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r15= c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("UNAUTHORIZED", r15.getCode().name());
        
        
        /////////////////
        //
        // Part 14
        //
        /////////////////
		
        // Send a new Access Token to update access rights and
        // join the same OSCORE group again with multiple roles
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER); // Allow this role too
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	Map<Short, CBORObject> params2 = new HashMap<>();
    	params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params2.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params2.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinSingleRoleUpdateAccessRights".getBytes(Constants.charset))); //Need different CTI
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        // Now the 'cnf' claim includes only a 'kid' with value the 'id'
        // used in the first Token and identifying the OSCORE_Input_Material
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KID_CBOR, Util.intToBytes(0));
        params2.put(Constants.CNF, cbor);
        CWT token2 = new CWT(params2);
        
        // Include only the Token now. If Id1 and Nonce1 were
        // included here too, the RS would silently ignore them
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token2.encode(ctx));
        
        asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
 	    // Posting the Token through an OSCORE-protected request
        // 
        // Normally, a client understands that the Token is indeed for updating access rights,
        // since the response from the AS does not include the 'cnf' parameter.
        CoapResponse rsRes2 = OSCOREProfileRequestsGroupOSCORE.postTokenUpdate("coap://localhost/authz-info",
        																	   asRes, askForSignInfo, askForEcdhInfo, ctxDB);
        assert(rsRes2.getCode() == CoAP.ResponseCode.CREATED);
        
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName));
        
        rsPayload = CBORObject.DecodeFromBytes(rsRes2.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        
        if (askForSignInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfoExpected, signInfo);
        }
        
        if (askForEcdhInfo) {
            Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
            
            if (rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
            
                Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
                ecdhInfo = CBORObject.NewArray();
                ecdhInfo = rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO));
                
                CBORObject ecdhInfoExpected = CBORObject.NewArray();
                CBORObject ecdhInfoEntry = CBORObject.NewArray();
                
                ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
                
                if (ecdhAlgExpected == null)
                    ecdhInfoEntry.Add(CBORObject.Null);
                else
                    ecdhInfoEntry.Add(ecdhAlgExpected);
                
                if (ecdhParamsExpected == null)
                    ecdhInfoEntry.Add(CBORObject.Null);
                else
                    ecdhInfoEntry.Add(ecdhParamsExpected);
                
                if (ecdhKeyParamsExpected == null)
                    ecdhInfoEntry.Add(CBORObject.Null);
                else
                    ecdhInfoEntry.Add(ecdhKeyParamsExpected);
                
                if (pubKeyEncExpected == null)
                    ecdhInfoEntry.Add(CBORObject.Null);
                else
                    ecdhInfoEntry.Add(pubKeyEncExpected);
                
                ecdhInfoExpected.Add(ecdhInfoEntry);

                Assert.assertEquals(ecdhInfoExpected, ecdhInfo);
                
            }
        }
		
		
        /////////////////
        //
        // Part 15
        //
        /////////////////
		
        // Send a new Join Request under the new Access Token
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000");

        requestPayload = CBORObject.NewMap();
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);

        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER); // Now this role is also allowed
    	cborArrayScope.Add(myRoles);
		
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForPubKeys) {
           
            getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
           
        }
        
        if (providePublicKey) {
            
        	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
        	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
        	if (gm_nonce == null)
        		Assert.fail("Error: the component N_S of the PoP evidence challence is null");
        	
            publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
            
            encodedPublicKey = null;
            switch (pubKeyEncExpected.AsInt32()) {
                case Constants.COSE_HEADER_PARAM_UCCS:
                    // Build a UCCS including the public key
                    encodedPublicKey = Util.oneKeyToUccs(publicKey, "");
                    break;
                case Constants.COSE_HEADER_PARAM_CWT:
                    // Build a CWT including the public key
                    // TODO
                    break;
                case Constants.COSE_HEADER_PARAM_X5CHAIN:
                    // Build/retrieve the certificate including the public key
                    // TODO
                    break;
            }
            requestPayload.Add(Constants.CLIENT_CRED, encodedPublicKey);
            
        	// Add the nonce for PoP of the Client's private key
            cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            offset = 0;
            privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            
            serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
            
       	    
       	    clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
            
            joinReq = new Request(Code.POST, Type.CON);
            joinReq.getOptions().setOscore(new byte[0]);
            joinReq.setPayload(requestPayload.EncodeToBytes());
            joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
            
            c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
            		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
            
            // Submit the request
            System.out.println("");
            System.out.println("Sent Join request to GM: " + requestPayload.toString());
            r2 = c1.advanced(joinReq);
            
            System.out.println("Received Join Reponse from the GM: " + CBORObject.DecodeFromBytes(r2.getPayload()).toString()); 
            
            Assert.assertEquals("CREATED", r2.getCode().name());
            
            if (r2.getOptions().getLocationPath().size() != 0) {
    	        System.out.print("Location-Path: ");
    	        System.out.println(r2.getOptions().getLocationPathString());
    	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
            }
           
            // The same dedicated URI has to have been returned
            Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
            
            responsePayload = r2.getPayload();
            joinResponse = CBORObject.DecodeFromBytes(responsePayload);
            
            Assert.assertEquals(CBORType.Map, joinResponse.getType());
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
            // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
            Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
            Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
           
            myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
           
            // Sanity check
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
            }
            if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
                Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
            }            
           
            // Check the presence, type and value of the public key encoding
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
            Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
            Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
            
            pubKeyEnc = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).AsInt32();
            
            Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
            Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
           
            Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
            Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
            Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
            Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
            Assert.assertNotNull(signAlg);
            Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
            Assert.assertNotNull(ecdhAlg);
            Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
           
            // Add default values for missing parameters
            if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
                myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
            if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
                myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
                  
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
            // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
            Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
            // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
            Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
            Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
           
            if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
                Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
                Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
            }
            if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
                Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
                Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
            }

            pubKeysArray = null;
            
            if (askForPubKeys) {
                Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
                Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
               
                pubKeysArray = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS));
                Assert.assertEquals(2, pubKeysArray.size());
               
                peerSenderId = new byte[] { (byte) 0x77 };
                peerSenderIdFromResponse = joinResponse.
                						   get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
                Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);

                peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
                
                peerPublicKeyRetrieved = null;
                peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
                switch (pubKeyEnc) {
                    case Constants.COSE_HEADER_PARAM_UCCS:
                        if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map)
                            peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                        else if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                            // Retrieve the public key from the CWT
                            // TODO
                        }
                        else {
                            Assert.fail("Invalid format of public key");
                        }
                        break;
                    case Constants.COSE_HEADER_PARAM_X5CHAIN:
                        // Retrieve the public key from the certificate
                        // TODO
                        break;
                    default:
                        Assert.fail("Invalid format of public key");
                }
                if (peerPublicKeyRetrieved == null)
                    Assert.fail("Invalid format of public key");
               
                // ECDSA_256
                if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                    Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                    Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
                }
               
                // EDDSA (Ed25519)
                if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                    Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                    Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
                }
                
                peerSenderId = new byte[] { (byte) 0x52 };
                peerSenderIdFromResponse = joinResponse.
						   get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
                
                peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
                Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
               
                peerPublicKeyRetrieved = null;
                peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
                switch (pubKeyEnc) {
                    case Constants.COSE_HEADER_PARAM_UCCS:
                        if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map)
                            peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                        else if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                            // Retrieve the public key from the CWT
                            // TODO
                        }
                        else {
                            Assert.fail("Invalid format of public key");
                        }
                        break;
                    case Constants.COSE_HEADER_PARAM_X5CHAIN:
                        // Retrieve the public key from the certificate
                        // TODO
                        break;
                    default:
                        Assert.fail("Invalid format of public key");
                }
                if (peerPublicKeyRetrieved == null)
                    Assert.fail("Invalid format of public key");
                
                // ECDSA_256
                if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                    Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                    Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
                }
               
                // EDDSA (Ed25519)
                if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                    Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                    Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                    Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
                }
                
                Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
                Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
                Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
                
                expectedRoles = 0;
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
                Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
                
                expectedRoles = 0;
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
                Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
                
            }
            else {
                Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
                Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            }
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
            Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
            Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
            

    		// Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
            Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
            Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
            
            gmPublicKeyRetrieved = null;
            gmPublicKeyRetrievedEncoded = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
            switch (pubKeyEnc) {
                case Constants.COSE_HEADER_PARAM_UCCS:
                    if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                        // Retrieve the public key from the UCCS
                        gmPublicKeyRetrieved = Util.uccsToOneKey(gmPublicKeyRetrievedEncoded);
                    }
                    else {
                        Assert.fail("Invalid format of Group Manager public key");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_CWT:
                    if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                        // Retrieve the public key from the CWT
                        // TODO
                    }
                    else {
                        Assert.fail("Invalid format of Group Manager public key");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_X5CHAIN:
                    // Retrieve the public key from the certificate
                    if (gmPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
                        // TODO
                    }
                    else {
                        Assert.fail("Invalid format of public key");
                    }
                    break;
                default:
                    Assert.fail("Invalid format of Group Manager public key");
            }
            if (gmPublicKeyRetrieved == null)
                Assert.fail("Invalid format of Group Manager public key");
            Assert.assertEquals(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)),
                                gmPublicKeyRetrieved.AsCBOR());
            
    		gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
    		
        	gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
        	rawGmPopEvidence = gmPopEvidence.GetByteString();
        	
        	gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
        	
        	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence));
        	
        }
    	
    }
    
    /**
     * Test post to Authz-Info, then join using multiple roles.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessGroupOSCOREMultipleRoles() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
        
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
                "coap://localhost/authz-info", asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost/feedca570000"));
        
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        byte[] gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();
        
        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS);
        
        if (askForSignInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfoExpected, signInfo);
        }
        
        if (askForEcdhInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
        	
        	if (rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
        	
	            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
	            ecdhInfo = CBORObject.NewArray();
	        	ecdhInfo = rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO));
	        	
		    	CBORObject ecdhInfoExpected = CBORObject.NewArray();
		    	CBORObject ecdhInfoEntry = CBORObject.NewArray();
		    	
		    	ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		    	
		    	if (ecdhAlgExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhAlgExpected);
		    	
		    	if (ecdhParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhParamsExpected);
		    	
		    	if (ecdhKeyParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhKeyParamsExpected);
	        	
	        	if (pubKeyEncExpected == null)
	        		ecdhInfoEntry.Add(CBORObject.Null);
	        	else
	        		ecdhInfoEntry.Add(pubKeyEncExpected);
		    	
	        	ecdhInfoExpected.Add(ecdhInfoEntry);
	
	        	Assert.assertEquals(ecdhInfoExpected, ecdhInfo);
	        	
        	}
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

		final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
		
		final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID signAlg = null;
		CBORObject signAlgCapabilities = CBORObject.NewArray();
		CBORObject signKeyCapabilities = CBORObject.NewArray();
		CBORObject signParams = CBORObject.NewArray();

		// ECDSA_256
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		signAlg = AlgorithmID.ECDSA_256;
		signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
		}
		    
		// EDDSA (Ed25519)
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		signAlg = AlgorithmID.EDDSA;
		signAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
		}
		    
		signParams.Add(signAlgCapabilities);
		signParams.Add(signKeyCapabilities);


		final AlgorithmID ecdhAlg = AlgorithmID.ECDH_SS_HKDF_256;
		CBORObject ecdhAlgCapabilities = CBORObject.NewArray();
		CBORObject ecdhKeyCapabilities = CBORObject.NewArray();
		CBORObject ecdhParams = CBORObject.NewArray();

		// ECDSA_256
		if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
		}
		    
		// X25519
		if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519); // Curve
		}
		    
		ecdhParams.Add(ecdhAlgCapabilities);
		ecdhParams.Add(ecdhKeyCapabilities);
        
		
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);
    	
        
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForPubKeys) {
           
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
           
        }
       
       if (providePublicKey) {
    	   
	    	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
	       	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
    	    if (gm_nonce == null)
    	    	Assert.fail("Error: the component N_S of the PoP evidence challence is null");
           
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
            
            CBORObject encodedPublicKey = null;
            switch (pubKeyEncExpected.AsInt32()) {
            	case Constants.COSE_HEADER_PARAM_UCCS:
        			// Build a UCCS including the public key
        			encodedPublicKey = Util.oneKeyToUccs(publicKey, "");
            		break;
            	case Constants.COSE_HEADER_PARAM_CWT:
            			// Build a CWT including the public key
            			// TODO
            		break;
            	case Constants.COSE_HEADER_PARAM_X5CHAIN:
            		// Build/retrieve the certificate including the public key
            		// TODO
            		break;
            }
        	requestPayload.Add(Constants.CLIENT_CRED, encodedPublicKey);
            
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
            
       	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
 
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
       
        int pubKeyEnc = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).AsInt32();
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        CBORObject pubKeysArray = null;
        if (askForPubKeys) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
           
            pubKeysArray = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS));
            Assert.assertEquals(2, pubKeysArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
            
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerPublicKeyRetrievedEncoded;
            
            peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
            switch (pubKeyEnc) {
	            case Constants.COSE_HEADER_PARAM_UCCS:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map)
	                	peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
	                else if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                	// TODO
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
	            		// TODO
	            	}
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            default:
	            	Assert.fail("Invalid format of public key");
            }
            if (peerPublicKeyRetrieved == null)
            	Assert.fail("Invalid format of public key");
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
            	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString(); 
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
            
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = joinResponse.
            	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
            peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
            switch (pubKeyEnc) {
	            case Constants.COSE_HEADER_PARAM_UCCS:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
	                    // Retrieve the public key from the UCCS
	                	peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	                
	            case Constants.COSE_HEADER_PARAM_CWT:
	                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                	// TODO
	                }
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
	            		// TODO
	            	}
	                else {
	                	Assert.fail("Invalid format of public key");
	                }
	                break;
	            default:
	            	Assert.fail("Invalid format of public key");
            }
            if (peerPublicKeyRetrieved == null)
            	Assert.fail("Invalid format of public key");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());

        

	    // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
	    Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
	    Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
	    
        OneKey gmPublicKeyRetrieved = null;
        CBORObject gmPublicKeyRetrievedEncoded = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    gmPublicKeyRetrieved = Util.uccsToOneKey(gmPublicKeyRetrievedEncoded);
                }
                else {
                	Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                	// TODO
                }
                else {
                	Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            default:
            	Assert.fail("Invalid format of Group Manager public key");
        }
        if (gmPublicKeyRetrieved == null)
        	Assert.fail("Invalid format of Group Manager public key");
        Assert.assertEquals(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)),
        					gmPublicKeyRetrieved.AsCBOR());
	
	    byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
	
	    CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
	    byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
	
	    PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
	
	    Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence));
        
        
        
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, keyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
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
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        pubKeysArray = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS));        
        
        byte[] peerSenderId;
        OneKey peerPublicKey;
        OneKey peerPublicKeyRetrieved = null;
        CBORObject peerPublicKeyRetrievedEncoded;
        byte[] peerSenderIdFromResponse;
        
        Assert.assertEquals(3, pubKeysArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();    
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(2);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(2).GetByteString();   
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        int expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        
        
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
        
        getPubKeys.Add(CBORObject.True);
        
        getPubKeys.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        getPubKeys.get(1).Add(myRoles);

        // Ask for the public keys of the other group members
        getPubKeys.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getPubKeys.get(2).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getPubKeys.get(2).Add(peerSenderId);
        
        requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        
        PubKeyReq = new Request(Code.FETCH, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        PubKeyReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        PubKeyReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        pubKeysArray = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS));
        Assert.assertEquals(3, pubKeysArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();      
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(0);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
            	if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;                
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();      
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(1);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }

        
        // Retrieve and check the public key this same node in the group
        peerSenderId = senderId;
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(2).GetByteString();   
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerPublicKeyRetrievedEncoded = pubKeysArray.get(2);
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                    // Retrieve the public key from the UCCS
                    peerPublicKeyRetrieved = Util.uccsToOneKey(peerPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (peerPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of public key");
        }
        if (peerPublicKeyRetrieved == null)
            Assert.fail("Invalid format of public key");
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
        }
       
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
            Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
            Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
        }
        
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
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
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_UCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
       
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, KeyDistributionResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }

        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the PUT method
        
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
        
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate))).PublicKey();

        CBORObject encodedPublicKey = null;
        switch (pubKeyEncExpected.AsInt32()) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                // Build a UCCS including the public key
                encodedPublicKey = Util.oneKeyToUccs(publicKey, "");
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                // Build a CWT including the public key
                // TODO
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Build/retrieve the certificate including the public key
                // TODO
                break;
        }
        requestPayload.Add(Constants.CLIENT_CRED, encodedPublicKey);

        // Add the nonce for PoP of the Client's private key
        byte[] cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(Constants.CNONCE, cnonce);

        // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
        int offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPairUpdate)))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
        byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
        byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
        offset += serializedGMNonceCBOR.length;
        System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);

        byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);

        if (clientSignature != null)
            requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        else
            Assert.fail("Computed signature is empty");
        
        Request PublicKeyUpdateReq = new Request(Code.POST, Type.CON);
        PublicKeyUpdateReq.getOptions().setOscore(new byte[0]);
        PublicKeyUpdateReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        PublicKeyUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(PublicKeyUpdateReq);

        System.out.println("");
        System.out.println("Sent Public Key Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 11
        //
        /////////////////
		
        // Send a Group Name and URI Retrieval Request, using the FETCH method
        
        System.out.println("Performing a Group Name and URI Retrieval Request using OSCORE to GM at " + "coap://localhost/ace-group");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource, CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject reqGroupIds = CBORObject.NewArray();
        reqGroupIds.Add(CBORObject.FromObject(groupId));
        
        requestPayload.Add(Constants.GID, reqGroupIds);
        
        Request GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r12 = c1.advanced(GroupNamesReq);
        
        System.out.println("");
        System.out.println("Sent Group Name and URI Retrieval Request FETCH request to GM");

        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(3, myObject.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GID)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GNAME)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.GURI)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GID)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GNAME)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(Constants.GURI)).getType());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GID)).size());
        Assert.assertArrayEquals(groupId, myObject.get(CBORObject.FromObject(Constants.GID)).get(0).GetByteString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GNAME)).size());
        Assert.assertEquals(groupName, myObject.get(CBORObject.FromObject(Constants.GNAME)).get(0).AsString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(Constants.GURI)).size());
        String expectedUri = new String("/" + rootGroupMembershipResource + "/" + groupName);
        Assert.assertEquals(expectedUri, myObject.get(CBORObject.FromObject(Constants.GURI)).get(0).AsString());
        
        // Send a second request, indicating the Group ID of a non existing OSCORE group
        
        requestPayload = CBORObject.NewMap();

        reqGroupIds = CBORObject.NewArray();
        byte[] groupId2 = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22 };
        reqGroupIds.Add(CBORObject.FromObject(groupId2));
        
        requestPayload.Add(Constants.GID, reqGroupIds);
        
        GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        r12 = c1.advanced(GroupNamesReq);
        
        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.ByteString, myObject.getType());
        Assert.assertEquals(0, myObject.size());
        
        
        /////////////////
        //
        // Part 12
        //
        /////////////////
        
        // Send a Group Manager Public Key Request, using the GET method

        System.out.println("Performing a Group Manager Public Key GET Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/gm-pub-key");

        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/gm-pub-key", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GmPubKeyReq = new Request(Code.GET, Type.CON);
        GmPubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r13 = c1.advanced(GmPubKeyReq);

        System.out.println("");
        System.out.println("Sent Group Manager Public Key GET request to GM");

        Assert.assertEquals("CONTENT", r13.getCode().name());

        myObject = CBORObject.DecodeFromBytes(r13.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        
        gmPublicKeyRetrieved = null;
        gmPublicKeyRetrievedEncoded = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        switch (pubKeyEnc) {
            case Constants.COSE_HEADER_PARAM_UCCS:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Map) {
                	// Retrieve the public key from the UCCS
                    gmPublicKeyRetrieved = Util.uccsToOneKey(gmPublicKeyRetrievedEncoded);
                }
                else {
                    Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of Group Manager public key");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                if (gmPublicKeyRetrievedEncoded.getType() == CBORType.ByteString) {
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of public key");
                }
                break;
            default:
                Assert.fail("Invalid format of Group Manager public key");
        }
        if (gmPublicKeyRetrieved == null)
            Assert.fail("Invalid format of Group Manager public key");
        Assert.assertEquals(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(gmPublicKeyStr)),
                            gmPublicKeyRetrieved.AsCBOR());
        
		gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
		
    	gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
    	rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
    	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence));
        
        
        /////////////////
        //
        // Part 13
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("Performing a Leaving Group Request using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r14 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r14.getCode().name());
        
        responsePayload = r14.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coap://localhost/ace-group/feedca570000/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r15 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("UNAUTHORIZED", r15.getCode().name());
        
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
   
}
