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

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

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
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
//import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

/**
 * Tests a client running the DTLS profile.
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspClientGroupOSCORE {

    private static byte[] key128
        = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static byte[] key128a 
        = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    private static String rpk = "piJYILr/9Frrqur4bAz152+6hfzIG6v/dHMG+SK7XaC2JcEvI1ghAKryvKM6og3sNzRQk/nNqzeAfZsIGAYisZbRsPCE3s5BAyYBAiFYIIrXSWPfcBGeHZvB0La2Z0/nCciMirhJb8fv8HcOCyJzIAE=";

    private static OneKey rsRPK;
    
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int countersignKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    private static String groupKeyPair;
    private static String strPublicKeyPeer1;
    private static String strPublicKeyPeer2;
    
    private static String rsAddrC;
    private static String rsAddrCS;
    
    private static CwtCryptoCtx ctx;
    
    private static RunTestServer srv;
    
    private static class RunTestServer implements Runnable {

        public RunTestServer() {
            //Do nothing
        }

        /**
         * Stop the server
         * @throws AceException 
         * @throws IOException 
         */
        public void stop() throws IOException, AceException {
            TestDtlspRSGroupOSCORE.stop();
        }

        @Override
        public void run() {
            try {
                TestDtlspRSGroupOSCORE.main(null); // M.T.
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    TestDtlspRSGroupOSCORE.stop();
                } catch (IOException | AceException e) {
                    System.err.println(e.getMessage());
                }
            }
        }

    }
    
    /**
     * Set up tests.
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws CoseException {
        srv = new RunTestServer();
        srv.run();       
        
        rsAddrCS = "coaps://localhost/authz-info";
        rsAddrC = "coap://localhost/authz-info";
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        rsRPK = new OneKey(CBORObject.DecodeFromBytes(
                Base64.getDecoder().decode(rpk)));
        
        // install needed cryptography providers
        try {
            org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
        } catch (Exception e) {
            System.err.println("Failed to install cryptography providers.");
            e.printStackTrace();
        }
    	
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
     * Cleans up after the tests 
     * @throws AceException 
     * @throws IOException 
     */
    @AfterClass
    public static void tearDown() throws IOException, AceException {
        srv.stop();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }

    /**
     * Test requesting some weird URI.
     * @throws AceException 
     * @throws CoseException 
     */
    @Test
    public void testWeirdUri() throws AceException, CoseException {
        CBORObject cbor = CBORObject.True;
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        CoapResponse r = DTLSProfileRequests.postToken(
                "coaps://localhost/authz-info/test", cbor, key);
        Assert.assertEquals("UNAUTHORIZED", r.getCode().name());
        CBORObject rPayload = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertEquals("{1: \"coaps://blah/authz-info/\"}", rPayload.toString());    
    }
    
    /**
     * Tests POSTing a token to authz-info
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testPostAuthzInfo() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException {  
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPAI".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx); 
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAI".getBytes(Constants.charset), 
                cti.GetByteString());
    }
    
    
    // M.T.
    /**
     * Tests POSTing a token to authz-info for
     * accessing an OSCORE group with a single role
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostAuthzInfoGroupOSCORESingleRole() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException, ConnectorException, IOException {  
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
        CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPAIGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload; 

        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
        // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	    	csAlg = AlgorithmID.ECDSA_256;
	        csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
	        csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }

    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
        
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore_app" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
     * Tests POSTing a token to authz-info for
     * accessing an OSCORE group with multiple roles
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostAuthzInfoGroupOSCOREMultipleRoles() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException, ConnectorException, IOException {  
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
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
                "tokenPAIGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
     // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
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

        	byte[] clientSignature = computeSignature(privKey, dataToSign);

        	if (clientSignature != null)
        	    requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        	    Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }

    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	    	csAlg = AlgorithmID.EDDSA;
	        csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
	        csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
	        csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));        
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams);
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());

        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
    
    /**
     * Tests connecting to the server, passing the token through 
     * psk-identity
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testTokenPskId() throws CoseException, IllegalStateException,
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPI".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);    
        CoapClient c = DTLSProfileRequests.getPskClient(new InetSocketAddress("localhost",
                CoAP.DEFAULT_COAP_SECURE_PORT), payload, key);
        c.setURI("coaps://localhost/helloWorld");
        CoapResponse r = c.get();
        Assert.assertEquals("CONTENT", r.getCode().name());
        Assert.assertEquals("Hello World!", r.getResponseText());    
    }
        
    /**
     *  Test passing a kid through psk-identity
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testKidPskId() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException, ConnectorException, IOException {
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        byte[] kid = new byte[] {0x01, 0x02, 0x03};
        CBORObject kidC = CBORObject.FromObject(kid);
        key.add(KeyKeys.KeyId, kidC);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost",
                CoAP.DEFAULT_COAP_SECURE_PORT), 
                kid, key);
        c.setURI("coaps://localhost/temp");
        CoapResponse r = c.get();
        Assert.assertEquals("CONTENT", r.getCode().name());
        Assert.assertEquals("19.0 C", r.getResponseText());
        
        //Try the same request again
        CoapResponse r2 = c.get();
        Assert.assertEquals("CONTENT", r2.getCode().name());
        Assert.assertEquals("19.0 C", r2.getResponseText());
    }
    
    
    /** 
     * Test post to authz-info with RPK then request
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostRPK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenRPK".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);    
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
              
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/helloWorld");
        CoapResponse r2 = c.get();
        Assert.assertEquals("CONTENT", r2.getCode().name());
        Assert.assertEquals("Hello World!", r2.getResponseText());  
    }
    
    // M.T.
    /** 
     * Test post to authz-info with RPK then request
     * for accessing an OSCORE Group with single role
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostRPKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostRPKGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);   
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
     // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }

    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
     * Test post to authz-info with RPK then request
     * for accessing an OSCORE Group with multiple roles
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostRPKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
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
                "tokenPostRPKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
     // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }

    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
    
    
    /** 
     * Test post to authz-info with RPK then request 
     * where RS rpk is not trusted.
     * 
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testUntrustedRPK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenRPK".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.FromObject(
                token.encode(ctx).EncodeToBytes());    
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
             
        OneKey bogusRPK = OneKey.generateKey(AlgorithmID.ECDSA_256);
        CoapClient c = DTLSProfileRequests.getRpkClient(key, bogusRPK);
        c.setURI("coaps://localhost/helloWorld");       
        try {
            c.get();
        } catch (IOException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Client should not accept DTLS connection");    
    }
    
    
    // M.T.
    /** 
     * Test post to authz-info with RPK then request 
     * where RS rpk is not trusted, when attempting
     * to access an OSCORE group with single role
     * 
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testUntrustedRPKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
        CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenRPKGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.FromObject(
                token.encode(ctx).EncodeToBytes());    
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
             
        OneKey bogusRPK = OneKey.generateKey(AlgorithmID.ECDSA_256);
        CoapClient c = DTLSProfileRequests.getRpkClient(key, bogusRPK);
        c.setURI("coaps://localhost/helloWorld");       
        try {
            c.get();
        } catch (IOException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Client should not accept DTLS connection");    
    }
    
    
    // M.T.
    /** 
     * Test post to authz-info with RPK then request 
     * where RS rpk is not trusted, when attempting
     * to access an OSCORE group with multiple roles
     * 
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testUntrustedRPKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        
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
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenRPKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.FromObject(
                token.encode(ctx).EncodeToBytes());    
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
             
        OneKey bogusRPK = OneKey.generateKey(AlgorithmID.ECDSA_256);
        CoapClient c = DTLSProfileRequests.getRpkClient(key, bogusRPK);
        c.setURI("coaps://localhost/helloWorld");       
        try {
            c.get();
        } catch (IOException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Client should not accept DTLS connection");    
    }
    
    
    /** 
     * Test post to authz-info with PSK then request
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostPSK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourPSK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
               
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPSK".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/helloWorld");
        CoapResponse r2 = c.get();
        Assert.assertEquals("CONTENT", r2.getCode().name());
        Assert.assertEquals("Hello World!", r2.getResponseText());  
    }    
    
    // M.T.
    /** 
     * Test post to authz-info with PSK then request
     * for joining an OSCORE Group with a single role
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostPSKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
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
        boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
    	// Client's asymmetric key pair
    	OneKey asymmetric = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String asymmetricKidStr = "ClientKeyPair";
        CBORObject asymmetricKid = CBORObject.FromObject(
        		asymmetricKidStr.getBytes(Constants.charset));
        asymmetric.add(KeyKeys.KeyId, asymmetricKid);
    	
        CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostPSKGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
     // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }

    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
     * Test post to authz-info with PSK then request
     * for joining an OSCORE Group with multiple roles
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    public void testPostPSKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
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
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
    	// Client's asymmetric key pair
    	OneKey asymmetric = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String asymmetricKidStr = "ClientKeyPair";
        CBORObject asymmetricKid = CBORObject.FromObject(
        		asymmetricKidStr.getBytes(Constants.charset));
        asymmetric.add(KeyKeys.KeyId, asymmetricKid);
    	
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
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
     // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
        	signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoRes = CBORObject.NewArray();
	    	if (csAlgExpected == null)
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csAlgExpected);
	    	if (csParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	else
	    		signInfoRes.Add(csParamsExpected);
	    	if (csKeyParamsMapExpected.isEmpty())
	    		signInfoRes.Add(CBORObject.Null);
	    	signInfoRes.Add(csKeyParamsExpected);

        	Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
        	pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        	Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
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
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
    	
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
    	// EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
    	
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));        
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
    * Test post to authz-info with PSK then request
    * for joining an OSCORE Group with multiple roles.
    * This will then be followed by derivation of a
    * Group OSCORE context based on the information
    * received from the GM.
    * @throws CoseException 
    * @throws AceException 
    * @throws InvalidCipherTextException 
    * @throws IllegalStateException 
    * @throws IOException 
    * @throws ConnectorException 
    */
    @Test
    public void testPostPSKGroupOSCOREMultipleRolesContextDerivation() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException {
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
        boolean askForSignInfo = true;
        boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;
        
        // Client's asymmetric key pair
        OneKey asymmetric = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String asymmetricKidStr = "ClientKeyPair";
        CBORObject asymmetricKid = CBORObject.FromObject(
                asymmetricKidStr.getBytes(Constants.charset));
        asymmetric.add(KeyKeys.KeyId, asymmetricKid);
        
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
                "tokenPostPSKGOMRDeriv".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
            payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
            payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOMRDeriv".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CBORObject signInfo = null;
        CBORObject pubKeyEnc = null;
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.RSNONCE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.RSNONCE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();
        
        // Group OSCORE specific values for the countersignature
        CBORObject csAlgExpected = null;
        Map<CBORObject, CBORObject> csParamsMapExpected = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMapExpected = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            csAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
            csKeyParamsMapExpected.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            csAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            csParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
            csKeyParamsMapExpected.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
            csKeyParamsMapExpected.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
        
        final CBORObject csParamsExpected = CBORObject.FromObject(csParamsMapExpected);
        final CBORObject csKeyParamsExpected = CBORObject.FromObject(csKeyParamsMapExpected);
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
            signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
            
            CBORObject signInfoRes = CBORObject.NewArray();
            if (csAlgExpected == null)
                signInfoRes.Add(CBORObject.Null);
            else
                signInfoRes.Add(csAlgExpected);
            if (csParamsMapExpected.isEmpty())
                signInfoRes.Add(CBORObject.Null);
            else
                signInfoRes.Add(csParamsExpected);
            if (csKeyParamsMapExpected.isEmpty())
                signInfoRes.Add(CBORObject.Null);
            signInfoRes.Add(csKeyParamsExpected);
        
            Assert.assertEquals(signInfo, signInfoRes);
        }
        
        if (askForPubKeyEnc) {
            Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.PUB_KEY_ENC)));
            Assert.assertEquals(CBORType.Number, cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC)).getType());
            pubKeyEnc = cbor.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
            Assert.assertEquals(pubKeyEnc, csKeyEncExpected);
        }
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
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
           
            byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
                requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
            else
                Assert.fail("Computed signature is empty");
            
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KTY)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.KTY)).getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.KTY)).AsInt32());
        
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));
        Assert.assertEquals(CBORType.Number, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)).getType());        
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
        
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            csAlg = AlgorithmID.ECDSA_256;
            csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
            csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            csAlg = AlgorithmID.EDDSA;
            csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
            csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
            csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }
        
        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)).GetByteString());
        
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(alg.AsCBOR(), myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(csAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)) == false)
            myMap.Add(OSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject(32));        
        
        Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PROFILE)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Number, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
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
        
        /* Context derivation below */

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
            //TODO: Change like this in other places too?
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
        sid_private_key = new OneKey(CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));

        //Now derive the actual context

        GroupOSCoreCtx ctx = null;
        try {
            ctx = new GroupOSCoreCtx(master_secret, true, algo, sid, kdf, rpl, 
                    master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
        } catch (OSException e) {
            System.err.println("Failed to derive Group OSCORE Context!");
            e.printStackTrace();
        }

        Assert.assertNotNull(ctx);

        //Finally add the recipient contexts from the coseKeySetArray
        for(int i = 0 ; i < coseKeySetArray.size() ; i++) {

            CBORObject key_param = coseKeySetArray.get(i);

            byte[] rid = null;
            CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
            if(rid_param.getType() == CBORType.ByteString) {
                rid = rid_param.GetByteString();
            }

            OneKey recipient_key = new OneKey(key_param);

            ctx.addRecipientContext(rid, recipient_key);
        }
        Assert.assertEquals(ctx.getRecipientContexts().size(), 2);
        System.out.println("Generated Group OSCORE Context:");
        Utility.printContextInfo(ctx);

    }
    
    
    /**
     * Test with a erroneous psk-identity
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
    @Ignore
    public void testFailPskId() throws ConnectorException, IOException {
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "someKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CoapClient c = DTLSProfileRequests.getPskClient(new InetSocketAddress("localhost",
                CoAP.DEFAULT_COAP_SECURE_PORT), "randomStuff".getBytes(), key);
        c.setURI("coaps://localhost/temp");
        try {
            c.get();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
            if (ex.getMessage().equals(
                    "java.lang.Exception: handshake flight 5 failed!")) {
                //Everything ok
                return;
            }
            Assert.fail("Hanshake should fail");
        }
        
        //Server should silently drop the handshake
        Assert.fail("Hanshake should fail");
    }
    
    
    /**
     * Test  passing a valid token through psk-identity
     * that doesn't match the request
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     
     */
    @Test
    public void testFailTokenNoMatch() throws IllegalStateException,
            InvalidCipherTextException, CoseException, AceException, ConnectorException, IOException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenFailNM".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "otherKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128a));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);
        CoapClient c = DTLSProfileRequests.getPskClient(new InetSocketAddress("localhost",
                CoAP.DEFAULT_COAP_SECURE_PORT), payload, key);
        c.setURI("coaps://localhost/temp");
        CoapResponse r = c.get();
        Assert.assertEquals("FORBIDDEN", r.getCode().name());
        CBORObject rPayload = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertEquals("{2: h'6F746865724B6579', 1: \"coaps://blah/authz-info/\"}", rPayload.toString());    
    }
    
    
    /**
     * Test  passing a valid token through psk-identity
     * that doesn't match the requested action.
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     
     */
    @Test
    public void testFailActionNoMatch() throws IllegalStateException,
            InvalidCipherTextException, CoseException, AceException, ConnectorException, IOException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenfailNAM".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "yetAnotherKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128a));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);    
        CoapClient c = DTLSProfileRequests.getPskClient(new InetSocketAddress("localhost",
                CoAP.DEFAULT_COAP_SECURE_PORT), payload, key);
        c.setURI("coaps://localhost/helloWorld");
        CoapResponse r = c.post("blah", MediaTypeRegistry.APPLICATION_JSON);
        Assert.assertEquals("METHOD_NOT_ALLOWED", r.getCode().name());
        CBORObject rPayload = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertEquals("{2: h'796574416E6F746865724B6579', 1: \"coaps://blah/authz-info/\"}", rPayload.toString());    
    }
    
    /**
     * Compute a signature, using the same algorithm and private key used in the OSCORE group to join
     * 
     * @param privKey  private key used to sign
     * @param dataToSign  content to sign
     
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
