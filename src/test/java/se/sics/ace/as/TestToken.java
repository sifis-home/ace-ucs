/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
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
package se.sics.ace.as;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
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
import se.sics.ace.Message;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.SQLConnector;

/**
 * Test the token endpoint class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestToken {
    
    private static OneKey publicKey;
    private static OneKey privateKey; 
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static SQLConnector db = null;
    private static String dbPwd = null;
    private static Token t = null;
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws AceException, SQLException, IOException, CoseException {
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            dbPwd = sb.toString().replace(System.getProperty("line.separator"), "");         
        } finally {
            br.close();
        }
        
        SQLConnector.createUser(dbPwd, "aceUser", "password", 
                "jdbc:mysql://localhost:3306");
        
        privateKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = privateKey.PublicKey();        
        
        db = new SQLConnector(null, null, null);
        db.init(dbPwd);
        
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        OneKey skey = new OneKey(keyData);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        profiles.add("coap_oscoap");
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        
        Set<String> auds = new HashSet<>();
        auds.add("sensors");
        auds.add("actuators");
        auds.add("failCWTpar");
        
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        
        Set<Integer> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        
        long expiration = 1000000L;
       
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, skey, publicKey);
        
        profiles.remove("coap_oscoap");
        scopes.clear();
        auds.clear();
        auds.add("sensors");
        auds.add("failTokenType");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscoap");
        scopes.add("co2");
        auds.clear();
        auds.add("actuators");
        auds.add("failTokenType");
        auds.add("failProfile");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, publicKey);
        
        profiles.clear();
        profiles.add("coap_dtls");
        auds.clear();
        auds.add("failProfile");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, publicKey);
        
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.add("co2");
        auds.clear();
        auds.add("failTokenNotImplemented");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.TEST_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs5", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, publicKey);
        
        profiles.clear();
        profiles.add("coap_oscoap");
        scopes.add("co2");
        auds.clear();
        keyTypes.clear();
        keyTypes.add("TST");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs6", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, publicKey);
        
        
        profiles.clear();
        profiles.add("coap_oscoap");
        scopes.add("co2");
        auds.clear();
        auds.add("failCWTpar");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs7", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, publicKey);
        
        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient(
                "clientA", profiles, null, null, keyTypes, null, publicKey);
  
        profiles.clear();
        profiles.add("coap_oscoap");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "rs1", keyTypes, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscoap");
        keyTypes.clear();
        keyTypes.add("TST");        
        db.addClient("clientC", profiles, "co2", "sensors", keyTypes, skey, null);
        
        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        keyTypes.add("PSK");
        db.addClient("clientD", profiles, null, null, keyTypes, skey, null);
        
        //Setup token entries
        String cti = "token1";
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000000L));   
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("cti", CBORObject.FromObject("token1"));
        db.addToken(cti, claims);
        
        cti = "token2";
        claims.clear();
        claims.put("scope", CBORObject.FromObject("temp"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(2000000L));
        claims.put("cti", CBORObject.FromObject("token2"));
        db.addToken(cti, claims);
        t = new Token("AS", 
                KissPDP.getInstance("src/test/resources/acl.json", db), db,
                new KissTime(), privateKey, 4); 
    }
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws AceException 
     * @throws SQLException 
     */
    @AfterClass
    public static void tearDown() throws AceException, SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306", connectionProps);
              
        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        String dropUser = "DROP USER 'aceUser'@'localhost';";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);
        stmt.close();
        rootConn.close();
        db.close();
    }
    
    
    /**
     * Test the token endpoint. Request should fail since it is unauthorized.
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnauthorized() throws Exception {
        Map<String, CBORObject> params = new HashMap<>();
        params.put("grant_type", Token.clientCredentialsStr);
        Message4Tests msg = new Message4Tests(-1, "client_1", "TestAS", params); 
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
    }
    

    /**
     * Test the token endpoint. Request should fail since the scope is missing.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailMissingScope() throws Exception {
        Map<String, CBORObject> params = new HashMap<>();
        params.put("grant_type", Token.clientCredentialsStr);
        Message4Tests msg = new Message4Tests(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
        response.getRawPayload())));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        cbor.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
        Assert.assertArrayEquals(response.getRawPayload(), 
                cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience is missing.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailMissingAudience() throws Exception {
        Map<String, CBORObject> params = new HashMap<>();
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("scope", CBORObject.FromObject("blah"));
        Message4Tests msg = new Message4Tests(-1, "clientA","TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
        response.getRawPayload())));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        cbor.Add(Constants.ERROR_DESCRIPTION, "No audience found for message");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the scope is not allowed.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailForbidden() throws Exception {  
        Map<String, CBORObject> params = new HashMap<>();
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("scope", CBORObject.FromObject("blah"));
        params.put("aud", CBORObject.FromObject("blubb"));
        Message msg = new Message4Tests(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), 
                cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support
     * a common token type.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleTokenType() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("failTokenType"));
        params.put("scope", CBORObject.FromObject("failTokenType"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode()
                == Message.FAIL_INTERNAL_SERVER_ERROR);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Audience incompatible on token type");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    } 
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support
     * a common profile.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleProfile() throws Exception {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("failProfile"));
        params.put("scope", CBORObject.FromObject("failProfile"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode()
                == Message.FAIL_INTERNAL_SERVER_ERROR);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "No compatible profile found");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience supports
     * an unknown token type.
     *  
     * @throws Exception
     */
    @Test
    public void testFailUnsupportedTokenType() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("rs5"));
        params.put("scope", CBORObject.FromObject("failTokenNotImplemented"));
        Message msg = new Message4Tests(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode()
                == Message.FAIL_NOT_IMPLEMENTED);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Unsupported token type");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the client failed to provide an
     * RPK. 
     * 
     * @throws Exception
     */
    @Test
    public void testFailRpkNotProvided() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("rs2"));
        params.put("scope", CBORObject.FromObject("r_light"));
        Message msg = new Message4Tests(-1, "clientD", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        cbor.Add(Constants.ERROR_DESCRIPTION, "Client failed to provide RPK");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the client provided an
     * unknown key type. 
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnknownKeyType() throws Exception {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("rs6"));
        params.put("scope", CBORObject.FromObject("r_valve"));
        Message msg = new Message4Tests(-1, "clientC", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode() == Message.FAIL_NOT_IMPLEMENTED);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Unsupported key type");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not
     * have a common CwtCryptoCtx
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleCwt() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("failCWTpar"));
        params.put("scope", CBORObject.FromObject("co2"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        System.out.println(Constants.unabbreviate(CBORObject.DecodeFromBytes(
                response.getRawPayload())));
        assert(response.getMessageCode() 
                == Message.FAIL_INTERNAL_SERVER_ERROR);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "No common security context found for audience");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should succeed with default scope.
     * 
     * @throws Exception
     */
    @Test
    public void testSucceedDefaultScope() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("aud", CBORObject.FromObject("rs1"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params.clear();
        params = Constants.unabbreviate(rparams);
        System.out.println(params.toString());
        assert(response.getMessageCode() 
                == Message.CREATED);
        CBORObject token = params.get("access_token");
        CWT cwt = CWT.processCOSE(token.EncodeToBytes(), CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        System.out.println("Access Token: " + cwt.toString());
    }
    
    /**
     * Test the token endpoint. 
     * Request should succeed with default audience.
     * 
     * @throws Exception
     */
    @Test
    public void testSucceedDefaultAud() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("scope", CBORObject.FromObject("co2"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params.clear();
        params = Constants.unabbreviate(rparams);
        System.out.println(params.toString());
        assert(response.getMessageCode() 
                == Message.CREATED);
        CBORObject token = params.get("access_token");
        CWT cwt = CWT.processCOSE(token.EncodeToBytes(), CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        System.out.println("Access Token: " + cwt.toString());
    }
    
    /**
     * Test the token endpoint, creating a REF token with multiple scopes, one
     * of which is not allowed. Request should succeed, but not give access to
     * scope "foobar"
     * 
     * @throws Exception
     */
    @Test
    public void testSucceed() throws Exception { 
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("grant_type", Token.clientCredentialsStr);
        params.put("scope", 
                CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put("aud", CBORObject.FromObject("rs3"));
        Message msg = new Message4Tests(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params.clear();
        params = Constants.unabbreviate(rparams);
        System.out.println(params.toString());
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get("access_token");
        Map<String, CBORObject> claims = db.getClaims(token.AsString());
        System.out.println(claims.toString());
        assert(claims.get("scope").AsString().contains("rw_valve"));
        assert(claims.get("scope").AsString().contains("r_pressure"));
        assert(!claims.get("scope").AsString().contains("foobar"));
    }
    
    /**
     * Test the token endpoint. Test purging expired tokens.
     * 
     * @throws Exception
     */
    @Test
    public void testPurge() throws Exception {
        Map<String, CBORObject> claims = db.getClaims("token1");
        assert(!claims.isEmpty());
        db.purgeExpiredTokens(1000001L);
        claims = db.getClaims("token1");
        assert(claims.isEmpty());
    }
    
    /**
     * Test the token endpoint. Test removing a specific token.
     * 
     * @throws Exception
     */
    @Test
    public void testRemoveToken() throws Exception { 
        Map<String, CBORObject> claims = db.getClaims("token2");
        assert(!claims.isEmpty());
        db.deleteToken("token2");
        claims = db.getClaims("token2");
        assert(claims.isEmpty());
    }
}
