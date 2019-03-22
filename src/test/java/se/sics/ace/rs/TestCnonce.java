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
package se.sics.ace.rs;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import org.junit.After;
import org.junit.Assert;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;

/**
 * Tests for the cnonce mechanism
 * 
 * @author Ludwig Seitz
 *
 */
public class TestCnonce {

    
    private static TokenRepository tr;     
    private static CBORObject pskCnf;
    static CwtCryptoCtx ctx;
    static OneKey symmetricKey;
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Set up tests.
     * @throws IOException 
     * @throws AceException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws IOException, AceException, CoseException  {
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
       
        createTR(valid);
        tr = TokenRepository.getInstance();
        
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), 
                "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());
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
                    + "tokens.json", null, new KissTime(), true, 500L);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null, new KissTime(), true, 500L);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    }
    
    
    /**
     * Test a successful round-trip with cnonce
     * 
     * @throws AceException 
     */
    @Test
    public void testSuccess() throws AceException {
       AsRequestCreationHints hints = new AsRequestCreationHints(
               "coaps://example.as.com/token", null, false, true);

       Request req = new Request(Code.GET);
       req.setURI("coap://localhost/temp");       
       CBORObject hintsCBOR = hints.getHints(req, tr, null);
       CBORObject cnonce = hintsCBOR.get(CBORObject.FromObject(Constants.CNONCE));
       System.out.println("client nonce: " + cnonce);
       Assert.assertNotNull(cnonce);
       
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("rs1"));
       params.put(Constants.CTI, CBORObject.FromObject(
               "token1".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       params.put(Constants.CNONCE, CBORObject.FromObject(cnonce));
       tr.addToken(params, ctx, null);      
    }
    
    /**
     * Test adding a token with missing cnonce claim
     * 
     * @throws AceException 
     */
    @Test
    public void testMissingCnonce() throws AceException {
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("rs1"));
       params.put(Constants.CTI, CBORObject.FromObject(
               "token2".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       this.thrown.expect(AceException.class);
       this.thrown.expectMessage("cnonce expected but not found");
       tr.addToken(params, ctx, null);      
    }
    
    /**
     * Test adding a token with unknown cnonce claim
     * 
     * @throws AceException 
     */
    @Test
    public void testInvalidCnonce() throws AceException {
       byte[] otherNonce = {0x00, 0x01, 0x02};
       
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("rs1"));
       params.put(Constants.CTI, CBORObject.FromObject(
               "token2".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       params.put(Constants.CNONCE, CBORObject.FromObject(otherNonce));
       this.thrown.expect(AceException.class);
       this.thrown.expectMessage("cnonce invalid");
       tr.addToken(params, ctx, null);      
    }
    
    /**
     * Test adding a token with invalid cnonce type
     * 
     * @throws AceException 
     */
    @Test
    public void testInvalidCnonceType() throws AceException {
       String otherNonce = "nonce";
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("rs1"));
       params.put(Constants.CTI, CBORObject.FromObject(
               "token2".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       params.put(Constants.CNONCE, CBORObject.FromObject(otherNonce));
       this.thrown.expect(AceException.class);
       this.thrown.expectMessage("Invalid cnonce type");
       tr.addToken(params, ctx, null);      
    }
    
    /**
     * Test adding a token with expired cnonce
     * 
     * @throws AceException 
     * @throws InterruptedException 
     */
    @Test
    public void testExpiredCnonce() throws AceException, InterruptedException {
        AsRequestCreationHints hints = new AsRequestCreationHints(
                "coaps://example.as.com/token", null, false, true);

        Request req = new Request(Code.GET);
        req.setURI("coap://localhost/temp");       
        CBORObject hintsCBOR = hints.getHints(req, tr, null);
        CBORObject cnonce = hintsCBOR.get(CBORObject.FromObject(Constants.CNONCE));
        System.out.println("client nonce: " + cnonce);
        Assert.assertNotNull(cnonce);
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CNONCE, CBORObject.FromObject(cnonce));
        TimeUnit.SECONDS.sleep(1);
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("cnonce invalid");
        tr.addToken(params, ctx, null);       
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
