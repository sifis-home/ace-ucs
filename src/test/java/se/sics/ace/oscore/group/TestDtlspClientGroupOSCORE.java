/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
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
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;

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
     */
    @Test
    public void testPostAuthzInfoGroupOSCORESingleRole() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException {  
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
        
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
        CBORObject payload = token.encode(ctx); 
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = key.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
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
     */
    @Test
    public void testPostAuthzInfoGroupOSCOREMultipleRoles() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException {  
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("listener");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
    	
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
        CBORObject payload = token.encode(ctx); 
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPAIGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = key.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());

        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
        }
        
    }
    
    /**
     * Tests connecting to the server, passing the token through 
     * psk-identity
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenPskId() throws CoseException, IllegalStateException,
            InvalidCipherTextException, AceException {
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
    
    
    // M.T.
    /**
     * Tests connecting to the server, passing the token through 
     * psk-identity, for accessing an OSCORE Group with single role
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenPskIdGroupOSCORESingleRole() throws CoseException, IllegalStateException,
            InvalidCipherTextException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
        
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
                "tokenPSKIdGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey2";
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
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = asymmetric.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r.getCode().name());
        
        byte[] responsePayload = r.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
        }

    }
    
    // M.T.
    /**
     * Tests connecting to the server, passing the token through 
     * psk-identity, for accessing an OSCORE Group with multiple roles
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenPskIdGroupOSCOREMultipeRoles() throws CoseException, IllegalStateException,
            InvalidCipherTextException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("listener");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
        
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
                "tokenPSKIdGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey3";
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
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();

        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = asymmetric.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r.getCode().name());
        
        byte[] responsePayload = r.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());

        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
        }

    }
    
    /**
     *  Test passing a kid through psk-identity
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testKidPskId() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
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
     */
    @Test
    public void testPostRPK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
     */
    @Test
    public void testPostRPKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
    	
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
        CBORObject payload = token.encode(ctx);   
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
              
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = key.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
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
     */
    @Test
    public void testPostRPKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("listener");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
    	
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
        CBORObject payload = token.encode(ctx);   
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrCS, payload, key);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
              
        CoapClient c = DTLSProfileRequests.getRpkClient(key, rsRPK);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = key.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
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
     */
    @Test
    public void testUntrustedRPK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
        } catch (RuntimeException ex) {
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
     */
    @Test
    public void testUntrustedRPKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
        } catch (RuntimeException ex) {
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
     */
    @Test
    public void testUntrustedRPKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String kidStr = "ourRPK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        
        Map<Short, CBORObject> params = new HashMap<>();
        
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("listener");
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
        } catch (RuntimeException ex) {
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
     */
    @Test
    public void testPostPSK() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
     */
    @Test
    public void testPostPSKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
        
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
        CBORObject payload = token.encode(ctx);
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = asymmetric.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
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
     */
    @Test
    public void testPostPSKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException {
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
    	String role2 = new String("listener");
    	boolean askForPubKeys = false;
    	boolean providePublicKey = false;
        
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
        CBORObject payload = token.encode(ctx);
        CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        CBORObject cbor = CBORObject.FromObject(r.getPayload());
        Assert.assertNotNull(cbor);
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey pubKey = asymmetric.PublicKey();
        	requestPayload.Add("client_cred", pubKey);
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
    	final AlgorithmID csAlg = AlgorithmID.EDDSA;
    	final CBORObject csParams = KeyKeys.OKP_Ed25519;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        
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
        
        Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// TODO
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
        }
        
}   
    
    
    /**
     * Test with a erroneous psk-identity
     */
    @Test
    public void testFailPskId() {
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
        } catch (RuntimeException ex) {
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
     
     */
    @Test
    public void testFailTokenNoMatch() throws IllegalStateException,
            InvalidCipherTextException, CoseException, AceException {
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
     
     */
    @Test
    public void testFailActionNoMatch() throws IllegalStateException,
            InvalidCipherTextException, CoseException, AceException {
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
}
