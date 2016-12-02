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
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.KissTime;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Test the introspection endpoint library.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestIntrospect {
    
    private static OneKey publicKey;
    private static OneKey privateKey;
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  
    private static SQLConnector db = null;
    private static String dbPwd = null;
    private static Introspect i = null;
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() 
            throws AceException, SQLException, IOException, CoseException {
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            dbPwd = sb.toString().replace(
                    System.getProperty("line.separator"), "");     
        } finally {
            br.close();
        }
       
        SQLConnector.createUser(dbPwd, "aceUser", "password", 
                "jdbc:mysql://localhost:3306");
            
        privateKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = privateKey.PublicKey();

        db = SQLConnector.getInstance(null, null, null);
        db.init(dbPwd);
        
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
                expiration, key128, publicKey);
                
        KissTime time = new KissTime();
        
        //Setup token entries
        String cti = "token1";
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(time.getCurrentTime()-1L));   
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("cti", CBORObject.FromObject("token1"));
        db.addToken(cti, claims);
        
        cti = "token2";
        claims.clear();
        claims.put("scope", CBORObject.FromObject("temp"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(
                time.getCurrentTime() + 2000000L));
        claims.put("cti", CBORObject.FromObject("token2"));
        db.addToken(cti, claims);

        i = new Introspect(
                KissPDP.getInstance("src/test/resources/acl.json", db), 
                db, time, publicKey);
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
     * Test the introspect endpoint. Request should fail since it is unauthorized.
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnauthorized() throws Exception {
        Message response = i.processMessage(
                new Message4Tests(-1, "unauthorizedRS", CBORObject.Null));
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add("error", "unauthorized_client");
        Assert.assertArrayEquals(response.getRawPayload(), 
                cbor.EncodeToBytes());
    }
    
    /**
     * Test the introspect endpoint. Request should fail since it
     * got a null payload.
     * 
     * @throws Exception
     */
    @Test
    public void testFailNoTokenSent() throws Exception {
        CBORObject nullObj = null;
        Message response = i.processMessage(
                new Message4Tests(-1, "rs1", nullObj));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add("error", "Must provide 'access_token' parameter");
        Assert.assertArrayEquals(response.getRawPayload(), 
                map.EncodeToBytes());
    }
    
    /**
     * Test the introspect endpoint. Expired token purged before introspected.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessPurgedInactive() throws Exception {
        ReferenceToken purged = new ReferenceToken("token1");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("access_token", purged.encode());
        Message response = i.processMessage(
                new Message4Tests(-1, "rs1", params));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        Constants.unabbreviate(rparams);
        System.out.println(rparams.toString());
        assert(rparams.get("active").equals(CBORObject.False));
    }
    
    /**
     * Test the introspect endpoint. Token does not exist.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessNotExistInactive() throws Exception {
        CBORObject notExist = CBORObject.FromObject("notExist");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("access_token", notExist);
        Message response = i.processMessage(
                new Message4Tests(-1, "rs1", params));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        Constants.unabbreviate(rparams);
        System.out.println(rparams.toString());
        assert(rparams.get("active").equals(CBORObject.False));
    }
    
    /**
     * Test the introspect endpoint. CWT token which is still valid.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessCWT() throws Exception {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put("aud", CBORObject.FromObject("rs3"));
        params.put("cti", CBORObject.FromObject("token2".getBytes()));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(
                privateKey, coseP.getAlg().AsCBOR());
        params.clear();
        params.put("access_token", token.encode(ctx));
        Message response = i.processMessage(
                new Message4Tests(-1, "rs1", params));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        Constants.unabbreviate(rparams);
        System.out.println(rparams.toString());
        assert(rparams.get("active").equals(CBORObject.True)); 
    }
    
    /**
     * Test the introspect endpoint. Expired token purged before introspected.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessRef() throws Exception {
        ReferenceToken t = new ReferenceToken("token2");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("access_token", t.encode());
        Message response = i.processMessage(
                new Message4Tests(-1, "rs1", params));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        Constants.unabbreviate(rparams);
        System.out.println(rparams.toString());
        assert(rparams.get("active").equals(CBORObject.True));
    }
}