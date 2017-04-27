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
package se.sics.ace.coap.dtlsProfile;

import java.io.File;
import java.io.IOException;
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

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.rs.dtlsProfile.DtlspTokenRepository;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissValidator;

/**
 * Test the DTLSProfileTokenRepository class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDtlspTokenRepository {

    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static OneKey symmetricKey;
    private static OneKey asymmetricKey;
    private static DtlspTokenRepository tr;
    private static CwtCryptoCtx ctx;
    
    
    /**
     * Set up tests.
     * 
     * @throws CoseException 
     * @throws IOException 
     * @throws AceException 
     */
    @BeforeClass
    public static void setUp() 
            throws CoseException, AceException, IOException {
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), 
                "psk".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData); 
        
        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        asymmetricKey.add(KeyKeys.KeyId, 
                CBORObject.FromObject("rpk".getBytes(Constants.charset)));
        
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
        
        DtlspTokenRepository.create(
                valid, "src/test/resources/tokens.json", null);
        tr = DtlspTokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
    }
    
    /**
     * Deletes the test file after the tests
     */
    @AfterClass
    public static void tearDown() {
        new File("src/test/resources/tokens.json").delete();
    }
    
    /**
     * Test adding a token with a symmetric cnf key
     * 
     * @throws AceException
     */
    @Test
    public void testTokenPSK() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        tr.addToken(params, ctx);
        
        OneKey key = tr.getKey("psk");
        Assert.assertArrayEquals(key128, key.get(KeyKeys.Octet_K).GetByteString());
        
        String sid = DtlspTokenRepository.makeSid(symmetricKey);
        Assert.assertEquals("psk", sid);
        
        Assert.assertEquals("psk",tr.getKid(sid));
        
    }
    
    /**
     * Test adding a token with a asymmetric cnf key
     * 
     * @throws AceException
     */
    @Test
    public void testTokenRPK() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", asymmetricKey.AsCBOR());
        tr.addToken(params, ctx);
        
        OneKey key = tr.getKey("rpk");
        Assert.assertArrayEquals(asymmetricKey.EncodeToBytes(), 
                key.EncodeToBytes());
        
        String sid = DtlspTokenRepository.makeSid(asymmetricKey);     
        Assert.assertEquals("rpk", tr.getKid(sid));
        
    }
    

}
