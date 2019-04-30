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
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.rs.AuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.DtlspPskStoreGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfilePskStoreGroupOSCORE class that implements fetching the access token from the
 * psk-identity in the DTLS handshake.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspPskStoreGroupOSCORE {

    private static DtlspPskStoreGroupOSCORE store = null;
   
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static AuthzInfoGroupOSCORE ai;

    private static TokenRepository tr;
    
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() throws AceException, IOException {
        
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions);
        myScopes.put("r_co2", myResource2);
        
        // M.T.
        // Adding the join resource, as one scope for each different combinations of
        // roles admitted in the OSCORE Group, with zeroed-epoch Group ID "feedca570000".
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put("feedca570000", actions2);
        myScopes.put("feedca570000_requester", myResource3);
        myScopes.put("feedca570000_listener", myResource3);
        myScopes.put("feedca570000_purelistener", myResource3);
        myScopes.put("feedca570000_requester_listener", myResource3);
        myScopes.put("feedca570000_requester_purelistener", myResource3);
        
        // M.T.
        Set<String> auds = new HashSet<>();
        auds.add("rs1"); // Simple test audience
        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes);
        
        // M.T.
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("rs2"));
        
        // M.T.
        // Include this resource as a join resource for Group OSCORE.
        // The resource name is the zeroed-epoch Group ID of the OSCORE group.
        valid.setJoinResources(Collections.singleton("feedca570000"));
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        createTR(valid);
        tr = TokenRepository.getInstance();
        
        ai = new AuthzInfoGroupOSCORE(tr, 
                Collections.singletonList("TestAS"), new KissTime(), null, 
                valid, ctx);
        store = new DtlspPskStoreGroupOSCORE(ai);
    }
    
    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(GroupOSCOREJoinValidator valid) throws IOException {
        try {
            TokenRepository.create(valid, TestConfig.testFilePath 
                    + "tokens.json", null, new KissTime(), false, null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null, new KissTime(), false, null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    }
    
    /**
     * Deletes the test file after the tests
     * 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException  {
        tr.close();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }  
    
    
    /**
     * Test with an invalid psk-identity (non-parseable)
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidPskId() throws Exception {
        byte[] key = store.getKey("blah");
        Assert.assertNull(key);
    }
    
    /**
     * Test with an invalid token in the psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidToken() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
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
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
        
        CBORObject tokenAsBytes = CBORObject.FromObject(
                tokenCB.EncodeToBytes());
        
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenAsBytes.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertNull(psk);
    }

    /**
     * Test with an valid psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskId() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
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
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
     
    /**
     * Test with only a kid in the CBOR structure
     * 
     * @throws Exception
     */
    @Test
    public void testKid() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>(); 
        claims.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        claims.put(Constants.AUD, CBORObject.FromObject("rs1"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token3".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        tr.addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with an valid psk-identity, when
     * joining an OSCORE group with a single role
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskIdGroupOSCORESingleRole() throws Exception {
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
                "token4".getBytes(Constants.charset)));
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
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with an valid psk-identity, when
     * joining an OSCORE group with multiple roles
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskIdGroupOSCOREMultipleRoles() throws Exception {
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
                "token5".getBytes(Constants.charset)));
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
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }

    // M.T.
    /**
     * Test with only a kid in the CBOR structure, when
     * joining an OSCORE group with a single role
     * 
     * @throws Exception
     */
    @Test
    public void testKidGroupOSCORESigleRole() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>();
        
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        claims.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        claims.put(Constants.AUD, CBORObject.FromObject("rs2"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token6".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        tr.addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with only a kid in the CBOR structure, when
     * joining an OSCORE group with multiple roles
     * 
     * @throws Exception
     */
    @Test
    public void testKidGroupOSCOREMultipleRoles() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>();
        
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
        claims.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        claims.put(Constants.AUD, CBORObject.FromObject("rs2"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token7".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        tr.addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
    
}
