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
package se.sics.ace.coap.oscoreProfile;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.TestConfig;
import se.sics.ace.as.Introspect;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler4Tests;

/**
 * 
 * @author Ludwig Seitz
 */
public class TestOscoreAuthzInfo {
    
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;

    private static AuthzInfo ai = null;
    private static Introspect i; 
    private static KissPDP pdp = null;
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() 
            throws SQLException, AceException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = key.PublicKey();

        
        OneKey sharedKey = new OneKey();
        sharedKey.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        sharedKey.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        sharedKey.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client1", profiles, null, null, keyTypes, null, 
                publicKey);
        db.addClient("client2", profiles, null, null, keyTypes, sharedKey,
                publicKey);

        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions);
        myScopes.put("r_co2", myResource2);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering token file from old test runs
        new File(TestConfig.testFilePath + "tokens.json").delete();
        
        pdp = new KissPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        i = new Introspect(pdp, db, new KissTime(), key);
        ai = new OscoreAuthzInfo(Collections.singletonList("TestAS"), 
                new KissTime(), 
                new IntrospectionHandler4Tests(i, "rs1", "TestAS"),
                valid, ctx, tokenFile, valid, false);
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        DBHelper.tearDownDB();
        pdp.close();
        i.close();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test invalid payload submission to OscoreAuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CoapReq request = CoapReq.getInstance(r);        
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Invalid payload");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test no-map CBOR submission to OscoreAuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoMapPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CBORObject foo = CBORObject.FromObject("bar");
        r.setPayload(foo.EncodeToBytes());
        CoapReq request = CoapReq.getInstance(r);        
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Payload to authz-info must be a CBOR map");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test map with no ACCESS_TOKEN
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoAccessTokenPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CBORObject foo = CBORObject.NewMap();
        foo.Add(Constants.OSCORE_Security_Context, "bar");
        r.setPayload(foo.EncodeToBytes());
        CoapReq request = CoapReq.getInstance(r);        
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
              "Missing mandatory parameter 'access_token'");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test fail in superclass AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailInAuthzInfo() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        CBORObject bogusToken = CBORObject.NewMap();
        bogusToken.Add(Constants.ACCESS_TOKEN, CBORObject.FromObject("bogus token"));
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                bogusToken);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test cnonce != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailCnonceNotByteString() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x01});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x01}), params);
        db.addCti2Client(ctiStr, "client1");  

        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNONCE, "blah");
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed or missing parameter cnonce");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test cnonce  == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailNullCnonce() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x02}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x02});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x02}), params);
        db.addCti2Client(ctiStr, "client1");  

        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNONCE, null);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed or missing parameter cnonce");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
  
    /**
     * Test OSCORE_Security_Context  == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailNullOsc() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x03}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.OSCORE_Security_Context, null);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x03});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x03}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Missing or malformed OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test OSCORE_Security_Context  != Map
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailOscNoMap() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x04}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.OSCORE_Security_Context, "blah");
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x04});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x04}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Missing or malformed OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload()); 
    }
    
    /**
     * Test alg  != AlgorithmID
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailAlgWrongType() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x05}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_ALG, "blah");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x05});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x05}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Malformed algorithm Id in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload()); 
    }
    
    /**
     * Test clientId  != byte-string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailClientIdNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x06}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_CLIENTID, "hugo");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x06});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x06}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Malformed client Id in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test contextId  != null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailContextIdNotNull() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x07}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_CONTEXTID, "blah");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x07});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x07}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, 
                "contextId must be null in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test kdf  != AlgorithmID
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailKdfWrongType() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_HKDF, "blah");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x08}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);          
        map.Add(Constants.ERROR_DESCRIPTION, 
                        "Malformed KDF in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
    
    /**
     * Test master_secret == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailMsNull() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x09}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, null);
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x09});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x09}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing master"
                + " secret in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());   
    } 
    
    /**
     * Test master_secret != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailMsNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x10}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, "very secret");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x10});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x10}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing master"
                + " secret in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());    
    } 
    
    
    
    /**
     * Test salt != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailSaltNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0a}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_SALT, "NaCl");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0a});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x0a}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed master"
                + " salt in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
    
    /**
     * Test serverId == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailServerIdNull() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0b}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_SERVERID, null);
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0b});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x0b}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing server id"
                + " in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
    
    /**
     * Test serverId != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailServerIdNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0c}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_SERVERID, "emil");
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0c});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x0c}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing server id"
                + " in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test failed OSCORE context creation exception
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailOscoreCtx() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0d}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, key128a);
        byte[] serverId = {0x05, 0x06};
        osc.Add(Constants.OS_SERVERID, serverId);
        osc.Add(Constants.OS_HKDF, AlgorithmID.HKDF_HMAC_AES_128.AsCBOR());
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0d});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x0d}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, 
                "Error while creating OSCORE security context: "
                + "HKDF algorithm not supported");
        CBORObject rC = CBORObject.DecodeFromBytes(response.getRawPayload());
        System.out.println(rC);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     * @throws OSException 
     */
    @Test
    public void testSuccess() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException, 
            OSException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0e}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = {0x09, 0x08};
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, key128a);
        byte[] serverId = {0x05, 0x06};
        osc.Add(Constants.OS_SERVERID, serverId);
        cbor.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0e});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x0e}), params);
        db.addCti2Client(ctiStr, "client1");  


        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        byte[] cnonce = {0x01, 0x02, 0x03};
        payload.Add(Constants.CNONCE, cnonce);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        HashMapCtxDB db = HashMapCtxDB.getInstance();
        OSCoreCtx osctx = db.getContext(clientId);
        OSCoreCtx osctx2 = new OSCoreCtx(key128a, 
                false, null, serverId, clientId, null, null, null, null);
        assert(osctx.equals(osctx2));
        
        
    }    
}
