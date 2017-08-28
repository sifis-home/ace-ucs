/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
package se.sics.ace.rs;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;

/**
 * Tests for the TokenRepository class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestTokenRepository {
    
    static OneKey asymmetricKey;
    static OneKey symmetricKey;
    static OneKey otherKey;
    static CwtCryptoCtx ctx;
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr; 
    private static CBORObject pskCnf;
    private static CBORObject rpkCnf;
    private static String ourKey = Base64.getEncoder().encodeToString(
            "ourKey".getBytes(Constants.charset));
    private static String rpk = Base64.getEncoder().encodeToString(
            "rpk".getBytes(Constants.charset));
    
    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() 
            throws AceException, CoseException, IOException {

        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        asymmetricKey.add(KeyKeys.KeyId, 
                CBORObject.FromObject("rpk".getBytes(Constants.charset)));
        
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
               
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), 
                "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        CBORObject otherKeyData = CBORObject.NewMap();
        otherKeyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        otherKeyData.Add(KeyKeys.KeyId.AsCBOR(), 
                "otherKey".getBytes(Constants.charset));
        otherKeyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(otherKeyData);
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<String>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        createTR(valid);
        tr = TokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());
        
        rpkCnf = CBORObject.NewMap();
        rpkCnf.Add(Constants.COSE_KEY_CBOR, 
                asymmetricKey.PublicKey().AsCBOR()); 
       
    }
    
    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(KissValidator valid) throws IOException {
        try {
            TokenRepository.create(valid, TestConfig.testFilePath 
                    + "tokens.json", null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    }
    
    /**
     * Deletes the test file after the tests
     */
    @AfterClass
    public static void tearDown() {
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test add token without scope
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoScope() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no scope");
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token without cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCti() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        tr.addToken(params, ctx, null);
        params.remove("cti"); //Gets added by tr.addToken()
        CBORObject cticb = CBORObject.FromObject(
                buffer.putInt(0, params.hashCode()).array());
        String cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
        Assert.assertNotNull(tr.getPoP(cti));
    }
    
    /**
     * Test add token with invalid cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCti() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        params.put("cti", CBORObject.FromObject("token1"));
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Cti has invalid format");
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token with duplicate cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenDuplicateCti() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Duplicate cti");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        tr.addToken(params, ctx, null);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", rpkCnf);
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token without cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no cnf");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token with unknown kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenUnknownKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token refers to unknown kid");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject(
                "blah".getBytes(Constants.charset)));
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token with invalid cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Malformed cnf claim in token");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blah",
                "blah".getBytes(Constants.charset));
        cnf.Add("blubb", CBORObject.FromObject(
                "blah".getBytes(Constants.charset)));
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
    }
    
    /**
     * Test add token with invalid Encrypt0
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenCnfInvalidEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Error while decrypting a cnf claim");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
                Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(key128a);
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
    }
    
    
    /**
     * Test add token with cnf without kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Malformed cnf claim in token");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blubb", CBORObject.FromObject(
                "blah".getBytes(Constants.charset)));
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
    }
    
    
    /**
     * Test add token with cnf with invalid kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("cnf contains invalid kid");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("blah"));
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
    }
    
    
    
    /**
     * Test add token with cnf containing COSE_Key
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfCoseKey() 
            throws AceException, IntrospectionException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        tr.addToken(params, ctx, null);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", rpkCnf);
        tr.addToken(params, ctx, null);
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(rpk, null, "co2", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.METHODNA, 
                tr.canAccess(rpk, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.FORBID,
                tr.canAccess(ourKey, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(ourKey, null, "temp", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, "temp", "GET", 
                        new KissTime(), null));
    }
    
    
    /**
     * Test add token with cnf containing known kid
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfKid() throws AceException, IntrospectionException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        tr.addToken(params, ctx, null);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject(
                "ourKey".getBytes(Constants.charset)));
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);
        
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(ourKey, null, "co2", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(ourKey, null, "temp", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, "temp", "GET", 
                        new KissTime(), null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException, 
            IntrospectionException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
                Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put("cnf", cnf);
        tr.addToken(params, ctx, null);

        Assert.assertEquals(TokenRepository.FORBID,
                tr.canAccess(ourKey, null, "co2", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", "POST", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(ourKey, null, "temp", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, "temp", "GET", 
                        new KissTime(), null));
    }
    
    
    /**
     * Test pollTokens()
     *
     * @throws AceException 
     */
    @Test
    public void testPollToken() throws AceException {
        KissTime time = new KissTime();
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        params.put("exp", CBORObject.FromObject(time.getCurrentTime()-1000));
        tr.addToken(params, ctx, null);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject(
                "ourKey".getBytes(Constants.charset)));
        params.put("cnf", cnf);
        params.put("exp", CBORObject.FromObject(time.getCurrentTime()+1000000));
        tr.addToken(params, ctx, null);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");
        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        
        tr.pollTokens(time);

        key1 = tr.getPoP("dG9rZW4x");
        key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertNull(key1);
        Assert.assertNotNull(key2);
    }
    
    /**
     * Test loading an existing token file
     * 
     * @throws AceException
     * @throws IOException 
     * @throws IntrospectionException 
     */
    @Test
    public void testLoad() 
            throws AceException, IOException, IntrospectionException {
        Set<String> resources = new HashSet<>();
        resources.add("temp");
        resources.add("co2");
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<String>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        TokenRepository tr2 = new TokenRepository(valid,
                TestConfig.testFilePath + "testTokens.json" , ctx);
        
        Assert.assertEquals(TokenRepository.OK,
                tr2.canAccess(rpk, null, "co2", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.OK,
                tr2.canAccess(ourKey, null, "temp", "GET", 
                        new KissTime(), null));  
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr2.canAccess("otherKey", null, "co2", "GET", 
                        new KissTime(), null));
        Assert.assertEquals(TokenRepository.METHODNA,
                tr2.canAccess(ourKey, null, "temp", "POST", 
                        new KissTime(), null)); 
        Assert.assertEquals(TokenRepository.FORBID,
                tr2.canAccess(ourKey, null, "co2", "GET", 
                        new KissTime(), null)); 
        tr2.close();
    }
    
    
    /**
     * Test getPoP()
     *
     * @throws AceException 
     */
    @Test
    public void testGetPoP() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", pskCnf);
        tr.addToken(params, ctx, null);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", rpkCnf);
        tr.addToken(params, ctx, null);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertArrayEquals(symmetricKey.EncodeToBytes(), 
                key1.EncodeToBytes());
        Assert.assertArrayEquals(
                asymmetricKey.PublicKey().EncodeToBytes(),
                key2.EncodeToBytes());
    }
    
    
    /**
     * Remove lingering token entries
     * @throws AceException 
     */
    @After
    public void cleanup() throws AceException {
        tr.removeToken("dG9rZW4x");
        tr.removeToken("dG9rZW4y");
    }
    
}
