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
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;

/**
 * Tests a client running the DTLS profile.
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspClientGroupOSCORE {

	private final String rootGroupMembershipResource = "ace-group";
	
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
        
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 1);
    	Security.insertProviderAt(EdDSA, 0);
    	
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
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // scopeEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
                
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		CBORObject csKeyEnc = CBORObject.FromObject(Constants.COSE_KEY);
			
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
		

        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
		
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
            byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
            System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
            offset += byteStringScope.length;
            System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
            offset += gm_sign_nonce.length;
            System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore_app" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
    
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
        
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        responsePayload = r1.getPayload();
        keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

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
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        
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
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// scopeEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
        
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
        	byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
        	System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
        	offset += byteStringScope.length;
        	System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
        	offset += gm_sign_nonce.length;
        	System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);

        	byte[] clientSignature = computeSignature(privKey, dataToSign);

        	if (clientSignature != null)
        	    requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        	    Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams);
        
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        responsePayload = r1.getPayload();
        keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
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
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	//scopeEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
    	
    	cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		CBORObject csKeyEnc = CBORObject.FromObject(Constants.COSE_KEY);
			
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
        
        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
        
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
            byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
            System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
            offset += byteStringScope.length;
            System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
            offset += gm_sign_nonce.length;
            System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
		/////////////////
		//
		// Part 3
		//
		/////////////////
        
		// Send a second Key Distribution Request, now as a group member
		
		System.out.println("\nPerforming a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
		
		r1 = c.get();
		System.out.println("");
		System.out.println("Sent Key Distribution request to GM as non member");
		
		Assert.assertEquals("CONTENT", r1.getCode().name());
		
		responsePayload = r1.getPayload();
		keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
		
		Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
		
		Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
		Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
		// Assume that "Group_OSCORE_Input_Material" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
		Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
		
		Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
		Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
		
		myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
		
		// Sanity check
		Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
		Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
		
		if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
			Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
		}
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
		
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        
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
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// scopeEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
        
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
            byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
            System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
            offset += byteStringScope.length;
            System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
            offset += gm_sign_nonce.length;
            System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        responsePayload = r1.getPayload();
        keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
        
        String groupName = new String("feedca570000");
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// String role1 = new String("requester");
        // scopeEntry.Add(role1);
        
        cborArrayScope.Add(scopeEntry);
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
        
        String groupName = new String("feedca570000");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// scopeEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(scopeEntry);
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
        String groupName = new String("feedca570000");
        boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
        int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // scopeEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		CBORObject csKeyEnc = CBORObject.FromObject(Constants.COSE_KEY);
			
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_alg)));

        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_params)));
        }
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
		

        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
        
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
            byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
            System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
            offset += byteStringScope.length;
            System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
            offset += gm_sign_nonce.length;
            System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        responsePayload = r1.getPayload();
        keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc))) {
        	Assert.assertEquals(csKeyEnc, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cs_key_enc)));
        }
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
        
        
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(2).AsInt32());
        
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
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForPubKeyEnc = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// scopeEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(scopeEntry);
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
        if (askForSignInfo || askForPubKeyEnc)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
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
        
        final CBORObject csKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        if (askForSignInfo || askForPubKeyEnc) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
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
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
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
		
        // Send a Key Distribution Request as a non-member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		CoapResponse r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        byte[] responsePayload = r1.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = keyDistributionResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 2
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using DTLS to GM at " + "coap://localhost/ace-group/feedca570000");
		
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
            byte [] dataToSign = new byte [byteStringScope.length + gm_sign_nonce.length + cnonce.length];
            System.arraycopy(byteStringScope, 0, dataToSign, offset, byteStringScope.length);
            offset += byteStringScope.length;
            System.arraycopy(gm_sign_nonce, 0, dataToSign, offset, gm_sign_nonce.length);
            offset += gm_sign_nonce.length;
            System.arraycopy(cnonce, 0, dataToSign, offset, cnonce.length);
       	   
       	    byte[] clientSignature = computeSignature(privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
        String nodeName = Utils.bytesToHex(senderId);
        String uriNodeResource = new String (rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
        responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)).GetByteString());
    	
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
        
        //Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        //GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
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
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
    
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("Performing a Key Distribution Request using DTLS to GM at " + "coaps://localhost/ace-group/feedca570000");
        
		r1 = c.get();
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        
        Assert.assertEquals("CONTENT", r1.getCode().name());
        
        responsePayload = r1.getPayload();
        keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
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
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.clientId)));
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
        // Part 4
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/num");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        CoapResponse r4 = c.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/active");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        CoapResponse r5 = c.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/policies");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(1, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_SN_SYNCH)).AsInt32());
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        Assert.assertEquals(CBORObject.False, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_PAIRWISE_MODE)));
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send a Public Key Request, using the GET method
        
        System.out.println("Performing a Public Key Request using OSCORE to GM at " + "coaps://localhost/ace-group/feedca570000/pub-key");
        
        c.setURI("coaps://localhost/" + rootGroupMembershipResource + "/" + groupName + "/pub-key");
                
        Request PubKeyReq = new Request(Code.GET, Type.CON);
        PubKeyReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c.advanced(PubKeyReq);
        
        System.out.println("");
        System.out.println("Sent Public Key Policies request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        
        // The content of the byte string should be a COSE_KeySet, to be processed accordingly
       
        byte[] coseKeySetByte = myObject.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
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
        
}   
    
    
    /**
     * Test with a erroneous psk-identity
     * @throws IOException 
     * @throws ConnectorException 
     */
    @Test
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
                    "org.eclipse.californium.scandium.dtls.DtlsHandshakeTimeoutException: Handshake flight 5 failed! Stopped by timeout after 4 retransmissions!")) {
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
