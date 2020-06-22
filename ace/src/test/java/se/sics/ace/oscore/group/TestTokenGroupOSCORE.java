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

import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

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
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.Token;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;

/**
 * Test the token endpoint class.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestTokenGroupOSCORE {
    
    private static OneKey publicKey;
    private static OneKey privateKey; 
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static SQLConnector db = null;
    private static Token t = null;
    private static String cti1;
    private static String cti2;
    private static GroupOSCOREJoinPDP pdp = null;
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws AceException, SQLException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        privateKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = privateKey.PublicKey(); 
        publicKey.add(KeyKeys.KeyId, CBORObject.FromObject(
                "myKey".getBytes(Constants.charset)));

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        OneKey skey = new OneKey(keyData);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        profiles.add("coap_oscore");
        
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
        
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        
        long expiration = 1000000L;
       
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, skey, skey, publicKey);
        
        profiles.remove("coap_oscore");
        scopes.clear();
        auds.clear();
        auds.add("sensors");
        auds.add("failTokenType");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscore");
        scopes.add("co2");
        auds.clear();
        auds.add("actuators");
        auds.add("failTokenType");
        auds.add("failProfile");
        keyTypes.clear();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, null, publicKey);
        
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
                expiration, null, null, publicKey);
        
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
                expiration, null, null, publicKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
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
                expiration, null, null, publicKey);
        
        
        profiles.clear();
        profiles.add("coap_oscore");
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
                expiration, null, null, publicKey);
        
        // M.T.
        // Add a further resource server "rs8" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add("feedca570000_requester");
        scopes.add("feedca570000_responder");
        scopes.add("feedca570000_monitor");
        scopes.add("feedca570000_requester_responder");
        auds.clear();
        auds.add("rs8");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs8", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, skey, publicKey);
        
        // M.T.
        // Add the resource server rs8 and its OSCORE Group Manager audience to the table OSCOREGroupManagers in the Database
        db.addOSCOREGroupManagers("rs8", auds);
        
        
        // M.T.
        // Add a further resource server "rs9" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add("feedca570000_requester");
        scopes.add("feedca570000_responder");
        scopes.add("feedca570000_monitor");
        scopes.add("feedca570000_requester_responder");
        auds.clear();
        auds.add("rs9");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs9", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, skey, publicKey);
        
        // M.T.
        // Add the resource server rs8 and its OSCORE Group Manager audience to the table OSCOREGroupManagers in the Database
        db.addOSCOREGroupManagers("rs9", auds);
        
        
        // M.T.
        // Add a further resource server "rs10" acting as OSCORE Group Manager
        // This resource server uses only CBOR Web Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add("feedca570000_requester");
        scopes.add("feedca570000_responder");
        scopes.add("feedca570000_monitor");
        scopes.add("feedca570000_requester_responder");
        auds.clear();
        auds.add("rs10");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs10", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, skey, publicKey);
        
        // Add the resource server rs9 and its OSCORE Group Manager audience to the table OSCOREGroupManagers in the Database
        db.addOSCOREGroupManagers("rs10", auds);
        
        
        // M.T.
        // Add a further resource server "rs11" acting as OSCORE Group Manager
        // This resource server uses only CBOR Web Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add("feedca570000_requester");
        scopes.add("feedca570000_responder");
        scopes.add("feedca570000_monitor");
        scopes.add("feedca570000_requester_responder");
        auds.clear();
        auds.add("rs11");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs11", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, skey, skey, publicKey);
        
        // Add the resource server rs9 and its OSCORE Group Manager audience to the table OSCOREGroupManagers in the Database
        db.addOSCOREGroupManagers("rs11", auds);
        
        
        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient(
                "clientA", profiles, null, null, 
                keyTypes, null, publicKey);
  
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "rs1", 
                keyTypes, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("TST");        
        db.addClient("clientC", profiles, "co2", "sensors", 
                keyTypes, skey, null);
        
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        keyTypes.add("PSK");
        db.addClient("clientD", profiles, null, null, 
                keyTypes, skey, null);
        
        profiles.clear();
        profiles.add("coap_dtls");
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("RPK");
        keyTypes.add("PSK");
        db.addClient("clientE", profiles, null, null, 
                keyTypes, skey, publicKey);
        
        RawPublicKeyIdentity rpkid 
            = new RawPublicKeyIdentity(publicKey.AsPublicKey());
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient(rpkid.getName(), profiles, null, null, 
                keyTypes, skey, publicKey);
        
        // M.T.
        // Add a further client "clientF" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientF", profiles, null, null, 
                keyTypes, skey, null);
        
        // M.T.
        // Add a further client "clientG" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientG", profiles, null, null, 
                keyTypes, skey, null);
        
        //Setup token entries
        byte[] cti = new byte[] {0x00};
        cti1 = Base64.getEncoder().encodeToString(cti);
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(1000000L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        db.addToken(cti1, claims);
        
        cti = new byte[]{0x01};
        cti2 = Base64.getEncoder().encodeToString(cti);
        claims.clear();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.EXP, CBORObject.FromObject(2000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        db.addToken(cti2, claims);
        

        
        
        pdp = new GroupOSCOREJoinPDP(db);
        pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addTokenAccess(rpkid.getName());
        pdp.addTokenAccess("clientA");
        pdp.addTokenAccess("clientB");
        pdp.addTokenAccess("clientC");
        pdp.addTokenAccess("clientD");
        pdp.addTokenAccess("clientE");
        
        // M.T.
        // Add also client "clientF" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientF");
        // Add also client "clientG" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientG");

        pdp.addAccess(rpkid.getName(), "rs3", "rw_valve");
        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        pdp.addAccess("clientA", "rs2", "r_light");
        pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");
        
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "co2");
        pdp.addAccess("clientB", "rs2", "r_light");
        pdp.addAccess("clientB", "rs2", "r_config");
        pdp.addAccess("clientB", "rs2", "failTokenType");
        pdp.addAccess("clientB", "rs3", "rw_valve");
        pdp.addAccess("clientB", "rs3", "r_pressure");
        pdp.addAccess("clientB", "rs3", "failTokenType");
        pdp.addAccess("clientB", "rs3", "failProfile");
        pdp.addAccess("clientB", "rs4", "failProfile");
        pdp.addAccess("clientB", "rs6", "co2");
        pdp.addAccess("clientB", "rs7", "co2");
        
        pdp.addAccess("clientC", "rs3", "r_valve");
        pdp.addAccess("clientC", "rs3", "r_pressure");
        pdp.addAccess("clientC", "rs6", "r_valve");

        pdp.addAccess("clientD", "rs1", "r_temp");
        pdp.addAccess("clientD", "rs1", "rw_config");
        pdp.addAccess("clientD", "rs2", "r_light");
        pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");
        pdp.addAccess("clientD", "rs1", "r_temp");
        

        pdp.addAccess("clientE", "rs3", "rw_valve");
        pdp.addAccess("clientE", "rs3", "r_pressure");
        pdp.addAccess("clientE", "rs3", "failTokenType");
        pdp.addAccess("clientE", "rs3", "failProfile");
        
        // M.T.
        pdp.addAccess("clientF", "rs2", "r_light");
        
        // Specify access right also for client "clientF" as a joining node of an OSCORE group.
        // On this Group Manager, this client is allowed to be requester, responder, requester+responder or monitor.
        pdp.addAccess("clientF", "rs8", "feedca570000_requester_monitor_responder");
        // On this Group Manager, this client is allowed to be requester or monitor.
        pdp.addAccess("clientF", "rs9", "feedca570000_requester_monitor");
        
        // On this Group Manager, this client is allowed to be requester, responder, requester+responder or monitor.
        pdp.addAccess("clientF", "rs10", "feedca570000_requester_monitor_responder");
        // On this Group Manager, this client is allowed to be requester or monitor.
        pdp.addAccess("clientF", "rs11", "feedca570000_requester_monitor");
        
        // Specify access right also for client "clientG" as a joining node of an OSCORE group.
        // This client is allowed to be only requester.
        pdp.addAccess("clientG", "rs8", "feedca570000_requester");
        pdp.addAccess("clientG", "rs10", "feedca570000_requester");
        
        // M.T.
        // Add the resource servers rs8, rs9, r10 and rs11 and their OSCORE Group Manager audience
        // to the table OSCOREGroupManagersTable in the PDP
        Set<String> rs8 = Collections.singleton("rs8");
        pdp.addOSCOREGroupManagers("rs8", rs8);
        Set<String> rs9 = Collections.singleton("rs9");
        pdp.addOSCOREGroupManagers("rs9", rs9);
        Set<String> rs10 = Collections.singleton("rs10");
        pdp.addOSCOREGroupManagers("rs10", rs10);
        Set<String> rs11 = Collections.singleton("rs11");
        pdp.addOSCOREGroupManagers("rs11", rs11);
        
        t = new Token("AS", pdp, db, new KissTime(), privateKey); 
    }
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        pdp.close();

        DBHelper.tearDownDB();
    }
    
    
    /**
     * Test the token endpoint. Request should fail since it is unauthorized.
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnauthorized() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        LocalMessage msg = new LocalMessage(-1, "client_1", "TestAS", params); 
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
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
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        LocalMessage msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
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
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("blah"));
        LocalMessage msg = new LocalMessage(-1, "clientA","TestAS", params);
        Message response = t.processMessage(msg);
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
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("blah"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("blubb"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failTokenType"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failTokenType"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode()
                == Message.FAIL_BAD_REQUEST);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failProfile"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failProfile"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode()
                == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INCOMPATIBLE_PROFILES);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs5"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failTokenNotImplemented"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);      
        assert(response.getMessageCode()
                == Message.FAIL_NOT_IMPLEMENTED);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Unsupported token type");
        Assert.assertArrayEquals(response.getRawPayload(), 
        cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support PSK
     * 
     * @throws Exception
     */
    @Test
    public void testFailPskNotSupported() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_light"));
        Message msg = new LocalMessage(-1, "clientD", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs6"));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_valve"));
        Message msg = new LocalMessage(-1, "clientC", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failCWTpar"));
        params.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() 
                == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt = CWT.processCOSE(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).EncodeToBytes(),
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        assert(cwt.getClaim(Constants.AUD).AsString().equals("rs1"));
    }
    
    /**
     * Test the token endpoint. 
     * Request should succeed with default audience.
     * 
     * @throws Exception
     */
    @Test
    public void testSucceedDefaultAud() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() 
                == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        assert(cwt.getClaim(Constants.SCOPE).AsString().equals("co2"));
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
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.get(Constants.SCOPE).AsString().contains("rw_valve"));
        assert(claims.get(Constants.SCOPE).AsString().contains("r_pressure"));
        assert(!claims.get(Constants.SCOPE).AsString().contains("foobar"));
        assert(!params.containsKey(Constants.PROFILE));
    }
    
    
    /**
     * Test with COSE_Encrypt in cnf parameter
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testSucceedCE() throws AceException, CoseException, 
            IllegalStateException, InvalidCipherTextException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("rw_valve"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        CBORObject rpk = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, 
                AlgorithmID.AES_CCM_16_128_128.AsCBOR(), 
                Attribute.PROTECTED);
        enc.SetContent(publicKey.EncodeToBytes());
        enc.encrypt(key128);
        rpk.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put(Constants.CNF, rpk);
        RawPublicKeyIdentity rpkid 
            = new RawPublicKeyIdentity(publicKey.AsPublicKey());
        Message msg = new LocalMessage(-1, rpkid.getName(), "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.get(Constants.SCOPE).AsString().contains("rw_valve"));
    }
    
    /**
     * Test with kid only in cnf parameter
     *
     * @throws AceException  
     */        
    @Test
    public void testSucceedCnfKid() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_pressure"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, publicKey.get(KeyKeys.KeyId));
        params.put(Constants.CNF, cnf);
        Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(params.containsKey(Constants.PROFILE));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.get(Constants.SCOPE).AsString().contains("r_pressure"));
        CBORObject cnf2 = claims.get(Constants.CNF);
        assert(cnf.equals(cnf2));
    }
    
    // M.T.
    /**
     * Test the token endpoint for asking access to an OSCORE group with a
     * single role, using a REF token with a scope including that single role.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCORESingleRoleREFToken() throws Exception { 
        String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	// The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
    	// The requested role is allowed in the specified group
    	Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        Message msg = new LocalMessage(-1, "clientF", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);     
        
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals("feedca570000"));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_MONITOR);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_MONITOR);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals("feedca570000"));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_RESPONDER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs9"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add((short)10);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_MONITOR);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
    }
    
    // M.T.
    /**
     * Test the token endpoint for asking access to an OSCORE group with a
     * single role, using a CWT with a scope including that single role.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCORESingleRoleCWT() throws Exception { 
        String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	// The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
    	// The requested role is allowed in the specified group
    	Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        Message msg = new LocalMessage(-1, "clientF", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);     
                
        CWT cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals("feedca570000"));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_MONITOR);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_MONITOR);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_RESPONDER);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs11"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add((short)10);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        cborArrayEntry.Add(Constants.GROUP_OSCORE_MONITOR);
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
    }
    
    
    // M.T.
    /**
     * Test the token endpoint for asking access to an OSCORE group with
     * multiple roles, using a REF token with a scope including multiple roles.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCOREMultipleRolesREFToken() throws Exception { 
        String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	// The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
    	// Both requested roles are allowed in the specified group
    	Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        Message msg = new LocalMessage(-1, "clientF", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);     
        
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Array) && cborArrayEntry.get(1).size() == 2);
        assert((cborArrayEntry.get(1).get(0).AsInt32() == Constants.GROUP_OSCORE_REQUESTER &&
        		cborArrayEntry.get(1).get(1).AsInt32() == Constants.GROUP_OSCORE_RESPONDER)
        		||
        	   (cborArrayEntry.get(1).get(0).AsInt32() == Constants.GROUP_OSCORE_RESPONDER &&
        	    cborArrayEntry.get(1).get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER));
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs9"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs8"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        claims = db.getClaims(ctiStr);
        
        byteStringScope = claims.get(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // None of the requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs9"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
                
    }
    
    // M.T.
    /**
     * Test the token endpoint for asking access to an OSCORE group with
     * multiple roles, using a CWT with a scope including multiple roles.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCOREMultipleRolesCWT() throws Exception { 
        String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	// The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
    	// Both requested roles are allowed in the specified group
    	Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        Message msg = new LocalMessage(-1, "clientF", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);     
        
        CWT cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Array) && cborArrayEntry.get(1).size() == 2);
        assert((cborArrayEntry.get(1).get(0).AsInt32() == Constants.GROUP_OSCORE_REQUESTER &&
        		cborArrayEntry.get(1).get(1).AsInt32() == Constants.GROUP_OSCORE_RESPONDER)
        		||
        	   (cborArrayEntry.get(1).get(0).AsInt32() == Constants.GROUP_OSCORE_RESPONDER &&
        	    cborArrayEntry.get(1).get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER));
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs11"));
        msg = new LocalMessage(-1, "clientF", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs10"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        token = params.get(Constants.ACCESS_TOKEN);     
        
        cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                CwtCryptoCtx.sign1Verify(
                publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        
        byteStringScope = cwt.getClaim(Constants.SCOPE).GetByteString();
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope = CBORObject.DecodeFromBytes(byteStringScope);
        assert(cborArrayScope.size() == 1);
        cborArrayEntry = cborArrayScope.get(0);
        assert(cborArrayEntry.getType().equals(CBORType.Array) && cborArrayEntry.size() == 2);
        assert(cborArrayEntry.get(0).getType().equals(CBORType.TextString));
        assert(cborArrayEntry.get(0).AsString().equals(gid));
        assert(cborArrayEntry.get(1).getType().equals(CBORType.Integer));
        assert(cborArrayEntry.get(1).AsInt32() == Constants.GROUP_OSCORE_REQUESTER);
        assert(!params.containsKey(Constants.PROFILE));
        
        
        // None of the requested ones is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs11"));
        msg = new LocalMessage(-1, "clientG", "TestAS", params);
        response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
        
    }
    
    /**
     * Test the token endpoint. Test purging expired tokens.
     * 
     * @throws Exception
     */
    @Test
    public void testPurge() throws Exception {
        Map<Short, CBORObject> claims = db.getClaims(cti1);
        assert(!claims.isEmpty());
        db.purgeExpiredTokens(1000001L);
        claims = db.getClaims(cti1);
        assert(claims.isEmpty());
    }
    
    /**
     * Test the token endpoint. Test removing a specific token.
     * 
     * @throws Exception
     */
    @Test
    public void testRemoveToken() throws Exception { 
        Map<Short, CBORObject> claims = db.getClaims(cti2);
        assert(!claims.isEmpty());
        db.deleteToken(cti2);
        claims = db.getClaims(cti2);
        assert(claims.isEmpty());
    }
    
    /**
     * Test the token endpoint by requesting multiple tokens and
     * checking that the cti counter is correctly adjusted.
     * This uses default audience and scope.
     * 
     * @throws Exception
     */
    @Test
    public void testMultiRequest() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        t.processMessage(msg);
        Long ctiCtrStart = db.getCtiCounter();
        for (int i=0; i<10; i++) {
            t.processMessage(msg);
        }
        Long ctiCtrEnd = db.getCtiCounter();
        assert(ctiCtrEnd == ctiCtrStart+10);
        
    }
    
    /**
     * Test the token endpoint by requesting multiple tokens and
     * checking that the cti counter is correctly adjusted.
     * This uses default audience and scope.
     * 
     * @throws Exception
     */
    @Test
    public void testTokenConfig() throws Exception {
        Set<Short> tokenConfig = new HashSet<>();
        tokenConfig.add(Constants.CTI);
        t = new Token("testAS2", pdp, db, new KissTime(),
                privateKey, tokenConfig, false);
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_pressure"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, publicKey.get(KeyKeys.KeyId));
        params.put(Constants.CNF, cnf);
        Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                CBORObject.DecodeFromBytes(
                        token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.containsKey(Constants.CTI));
        assert(claims.size() == 1);     
        db.deleteToken(ctiStr);
        t = new Token("AS", pdp, db, new KissTime(), privateKey); 
    }
    
    /**
     * Test the grant flow.
     * 
     * @throws Exception
     */
    @Test
    public void testGrant() throws Exception {
        //Create the grant
        byte[] ctiB = new byte[] {0x00, 0x01};
        String cti = Base64.getEncoder().encodeToString(ctiB);
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.AUD, CBORObject.FromObject("rs1"));
        claims.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, publicKey.get(KeyKeys.KeyId));
        claims.put(Constants.CNF, cnf);
        CWT cwt = new CWT(claims);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CBORObject cwtCB = cwt.encode(ctx);
        Map<Short, CBORObject> rsInfo = new HashMap<>(); 
        rsInfo.put(Constants.ACCESS_TOKEN, 
                CBORObject.FromObject(cwtCB.EncodeToBytes()));
        rsInfo.put(Constants.CNF, cnf);
        db.addGrant("testGrant", cti, claims, rsInfo);
        
        //Prepare the request
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.authzCode);
        params.put(Constants.CODE,  
                CBORObject.FromObject("testGrant"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt2 = CWT.processCOSE(CBORObject.DecodeFromBytes(
                token.GetByteString()).EncodeToBytes(), 
                ctx);
        claims = cwt2.getClaims();
        assert(claims.get(Constants.SCOPE).AsString().contains("r_temp"));
        assert(claims.get(Constants.AUD).AsString().contains("rs1"));     
    }
    
}
