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
package se.sics.ace.as;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.AceException;


/**
 * Test the database connection classes.
 * 
 * @author Ludwig Seitz and Marco Rasori
 *
 */
public class TestDB {
  
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    static String testUsername = "userace";

    static SQLConnector db = null;

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
                expiration, null, skey, publicKey);
        
        profiles.remove("coap_oscore");
        scopes.clear();
        auds.remove("actuators");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscore");
        scopes.add("co2");
        auds.clear();
        auds.add("actuators");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, null, publicKey);
        
        
        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("clientA", profiles, null, null, keyTypes, null,
                publicKey);
  
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "sensors", keyTypes, 
                skey, null);
        
        //Setup token entries
        String cid = "token1";
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(1000000L));   
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cid, claims);
        
        cid = "token2";
        claims.clear();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.EXP, CBORObject.FromObject(2000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        db.addToken(cid, claims);
    }

    /**
     * Removes DB setup.
     * @throws SQLException
     * @throws AceException
     * @throws IOException
     */
    @AfterClass
    public static void tearDown() throws AceException
    {
        DBHelper.tearDownDB();
        db.close();
    }

    /**
     * Test adding a RS that is already in the DB
     * (should fail)
     * 
     * @throws Exception 
     */
    @Test (expected=AceException.class)
    public void testAddDuplicateRS() throws Exception {
        Set<String> profiles = new HashSet<>();    
        Set<String> scopes = new HashSet<>();
        Set<String> auds = new HashSet<>();      
        Set<String> keyTypes = new HashSet<>();      
        Set<Short> tokenTypes = new HashSet<>();
        Set<COSEparams> cose = new HashSet<>();        
        long expiration = 1000000L;
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, null, null, null);  
        Assert.fail("Duplicate RS was added to DB");
    }
    
    /**
     * Test adding a client that is already in the DB
     * (should fail)
     * 
     * @throws Exception 
     */
    @Test (expected=AceException.class)
    public void testAddDuplicateClient() throws Exception {
        Set<String> profiles = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        db.addClient("clientA", profiles, null, null, 
                keyTypes, null, null);
        Assert.fail("Duplicate client was added to DB");
    }

    /**
     * Test the getProfiles() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetProfiles() throws Exception {
        String profile = db.getSupportedProfile("clientA", 
                Collections.singleton("sensors"));
        assert(profile.equals("coap_dtls"));
        
        profile = db.getSupportedProfile("sensors", 
                Collections.singleton("clientB"));
        assert(profile == null);
    }
        
    /**
     * Test the getKeyTypes() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyTypes() throws Exception {
            
        Set<String> keyType = db.getSupportedPopKeyTypes( 
                Collections.singleton("sensors"));
        assert(keyType.contains("RPK"));
        
        Set<String> allRS = new HashSet<>();
        allRS.add("rs1");
        allRS.add("rs2");
        allRS.add("rs3");
        keyType =  db.getSupportedPopKeyTypes(allRS);
        assert(keyType == null);
    }
    
    /**
     * Test the getTokenType() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetTokenType() throws Exception {
        Short tokenType = db.getSupportedTokenType(
                Collections.singleton("sensors"));
        assert(tokenType.equals(AccessTokenFactory.CWT_TYPE));
    }
    
    /**
     * Test the getTokenType() method with a set of audiences
     * 
     * @throws Exception 
     */
    @Test
    public void testGetTokenTypeAudSet() throws Exception {
        Set<String> aud = new HashSet<>();
        aud.add("sensors");
        aud.add("actuators");
        Short tokenType = db.getSupportedTokenType(aud);
        assert(tokenType.equals(AccessTokenFactory.CWT_TYPE));
    }
    
    
    /**
     * Test the getCose() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCose() throws Exception {
        COSEparams cose = db.getSupportedCoseParams(
                Collections.singleton("actuators"));
        assert(cose == null);
        cose = db.getSupportedCoseParams(Collections.singleton("sensors"));
        System.out.println(cose.toString());
        assert(cose.toString().equals("18:-7:-6")); 
    }
    
    /**
     * Test the isScopeSupported() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testIsScopeSupported() throws Exception {
       boolean supported = db.isScopeSupported("actuators", "co2");
       assert(supported);
       
       supported = db.isScopeSupported("sensors", "temp");
       assert(!supported);
    }
    
    
    /**
     * Test the getDefaultScope() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetDefaultScope() throws Exception {
        String scope = db.getDefaultScope("clientB");
        assert(scope.equals("co2"));
        
        scope  = db.getDefaultScope("clientA");
        Assert.assertNull(scope);

    }
    
    /**
     * Test the getDefaultAudience() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetDefaultAudience() throws Exception {
        String aud = db.getDefaultAudience("clientB");
        assert(aud.equals("sensors"));
               
        aud = db.getDefaultAudience("clientA");
        Assert.assertNull(aud);
    }

    /**
     * Test the getRSS(aud) function.
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRSS() throws Exception {
        Set<String> rss = db.getRSS("actuators");
        assert(rss.contains("rs1"));
        assert(rss.contains("rs3"));
        
        rss = db.getRSS("sensors");
        assert(rss.contains("rs1"));
        assert(rss.contains("rs2"));
        
    }

    /**
     * Test the getRSS() function.
     *
     * @throws Exception
     */
    @Test
    public void testGetAllRSS() throws Exception {
        Set<String> rss = db.getRSS();
        assert(rss.contains("rs1"));
        assert(rss.contains("rs2"));
        assert(rss.contains("rs3"));
    }
    
    /**
     * Test the getExpTime() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetExpTime() throws Exception {
        long exp = db.getExpTime(Collections.singleton("rs1"));
        assert(exp == 1000000L);
        
        exp =  db.getExpTime(Collections.singleton("rs2"));
        assert(exp == 300000L);

    }

    /**
     * Test the getAudiences() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetAudiences() throws Exception {
        Set<String> auds = db.getAudiences("rs1");
        assert(auds.contains("sensors"));
        assert(auds.contains("actuators"));
              
        auds = db.getAudiences("rs2");
        assert(auds.contains("sensors"));
        assert(!auds.contains("actuators"));
                
    }
    
    /**
     * Test the getRsPSK() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsPSK() throws Exception {
       OneKey key = db.getRsTokenPSK("rs1");
       Assert.assertArrayEquals(key128, 
               key.get(KeyKeys.Octet_K).GetByteString());
             
       key = db.getRsTokenPSK("rs3");
       Assert.assertNull(key);
    }
    
    /**
     * Test the getRsRPK() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsRPK() throws Exception {
        OneKey rpk = db.getRsRPK("rs1");
        Assert.assertArrayEquals(
                publicKey.EncodeToBytes(), rpk.EncodeToBytes());           
        rpk = db.getRsRPK("rs2");
        Assert.assertNull(rpk);
    }
    
    /**
     * Test the getCPSK() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCPSK() throws Exception {
        OneKey key = db.getCPSK("clientB");
        Assert.assertArrayEquals(key128, 
                key.get(KeyKeys.Octet_K).GetByteString());
        
        key  = db.getCPSK("clientA");
        Assert.assertNull(key);
    }
    
    /**
     * Test the getCRPK() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCRPK() throws Exception {
        OneKey rpk = db.getCRPK("clientA");
        Assert.assertArrayEquals(
                publicKey.EncodeToBytes(), rpk.EncodeToBytes());   
        rpk = db.getCRPK("clientB");
        Assert.assertNull(rpk);
    }

    /**
     * Test the deleteRS() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testDeleteRS() throws Exception {
        Set<String> profiles = new HashSet<>();
        profiles.add("foo");
        Set<String> scopes = new HashSet<>();
        Set<String> auds = new HashSet<>();      
        Set<String> keyTypes = new HashSet<>();  
        keyTypes.add("PSK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        Set<COSEparams> cose = new HashSet<>();      
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        long expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, null, null, key);  
        
        
        Set<String> present = db.getAudiences("rs4");
        assert(present.contains("rs4"));
       
        db.deleteRS("rs4");
        present = db.getAudiences("rs4");
        assert(present.isEmpty());  
    }

    /**
     * Test the deleteClient() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testDeleteClient() throws Exception {
        Set<String> profiles = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        byte[] keyBytes = {0x00, 0x01};
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(keyBytes));
        OneKey key = new OneKey(keyData);

        profiles.add("blah");
        keyTypes.add("RPK");
        db.addClient("clientC", profiles, null, null, 
                keyTypes, key, null);
            
       OneKey newKey = db.getCPSK("clientC");
       Assert.assertArrayEquals(key.EncodeToBytes(), newKey.EncodeToBytes());

       db.deleteClient("clientC");
       newKey = db.getCPSK("clientC");
       Assert.assertNull(newKey);
    }

    /**
     * Test the getClaims and deleteToken() methods. 
     * 
     * @throws Exception 
     */
    @Test
    public void testTokenTables() throws Exception {
        
        byte[] cti = new byte[]{0x01, 0x02};
        String ctiStr = Base64.getEncoder().encodeToString(cti);
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(1000000L));   
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        db.addToken(ctiStr, claims);
                
        Map<Short, CBORObject> result = db.getClaims(ctiStr);
         
        //Checks that there are claims
        assert(!result.isEmpty());
                
        db.deleteToken(ctiStr);
        result = db.getClaims(ctiStr);
        assert(result.isEmpty());
    }
    
    /**
     * Test the purgeExpiredTokens() method. 
     * 
     * @throws Exception 
     */
    @Test
    public void testPurgeExpiredTokens() throws Exception {
        byte[] cti = new byte[]{0x01, 0x03};
        String ctiStr = Base64.getEncoder().encodeToString(cti);
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(1000L));   
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        db.addToken(ctiStr, claims);
        
        db.purgeExpiredTokens(1001L);
       
        Map<Short, CBORObject> result = db.getClaims(ctiStr);
        assert(result.isEmpty());
    }
    
    
    /**
     * Tests for the addCti2Peers(), getClient4Cti() and getCtis4Client()
     * methods.
     * 
     * @throws AceException
     */
    @Test (expected=AceException.class)
    public void testGetClient4Cti() throws AceException {
        db.addCti2Peers("cti1", "client1", new HashSet<String>(){{add("aud1");}});
        db.addCti2Peers("cti2", "client1", new HashSet<String>(){{add("aud1");}});
        db.addCti2Peers("cti3", "client2", new HashSet<String>(){{add("aud1");}});
        String client = db.getClient4Cti("cti1");
        assert(client.equals("client1"));
        client = db.getClient4Cti("cti2");
        assert(client.equals("client1"));
        Set<String>ctis = db.getCtis4Client("client1");
        assert(ctis != null && !ctis.isEmpty());
        assert(ctis.contains("cti1"));
        assert(ctis.contains("cti2"));
        assert(!ctis.contains("cti3"));
        client = db.getClient4Cti("nothing");
        assert(client == null);
        ctis = db.getCtis4Client("a girl is no one");
        assert(ctis.isEmpty());
        db.addCti2Peers("cti1", "client2", new HashSet<String>(){{add("aud1");}});
        Assert.fail("Duplicate Cti was added to DB");   
    }


    /**
     * Tests for the addCtis2Peers() and getCtis4Rs() methods
     * that use the TokenLog table.
     *
     * @throws AceException
     */
    @Test (expected=AceException.class)
    public void testTokenLog() throws AceException {
        db.addCti2Peers("cti1", "client1", new HashSet<String>(){{add("XXXrs1,rs2,rs3,rs4");}});
        db.addCti2Peers("cti2", "client1", new HashSet<String>(){{add("rs2,rs3XXX");}});
        db.addCti2Peers("cti3", "client2", new HashSet<String>(){{add("rs4,rs1");}});
        db.addCti2Peers("cti4", "client2", new HashSet<String>(){{add("rs1,rs2XXX,rs4");}});
        db.addCti2Peers("cti5", "client2", new HashSet<String>(){{add("rs1");}});

        Set<String> ctisOfRs1 = db.getCtis4Rs("rs1");
        Set<String> ctisOfRs2 = db.getCtis4Rs("rs2");
        Set<String> ctisOfRs3 = db.getCtis4Rs("rs3");
        Set<String> ctisOfRs4 = db.getCtis4Rs("rs4");
        Set<String> ctisOfRs5 = db.getCtis4Rs("rs5");

        assert(!ctisOfRs1.contains("cti1"));
        assert(!ctisOfRs1.contains("cti2"));
        assert(ctisOfRs1.contains("cti3"));
        assert(ctisOfRs1.contains("cti4"));
        assert(ctisOfRs1.contains("cti5"));

        assert(ctisOfRs2.contains("cti1"));
        assert(ctisOfRs2.contains("cti2"));
        assert(!ctisOfRs2.contains("cti3"));
        assert(!ctisOfRs2.contains("cti4"));
        assert(!ctisOfRs2.contains("cti5"));

        assert(ctisOfRs3.contains("cti1"));
        assert(!ctisOfRs3.contains("cti2"));
        assert(!ctisOfRs3.contains("cti3"));
        assert(!ctisOfRs3.contains("cti4"));
        assert(!ctisOfRs3.contains("cti5"));

        assert(ctisOfRs4.contains("cti1"));
        assert(!ctisOfRs4.contains("cti2"));
        assert(ctisOfRs4.contains("cti3"));
        assert(ctisOfRs4.contains("cti4"));
        assert(!ctisOfRs4.contains("cti5"));

        assert(ctisOfRs5.isEmpty());

        Set<String> ctisOfClient1 = db.getCtis4Client("client1");
        Set<String> ctisOfClient2 = db.getCtis4Client("client2");

        assert(ctisOfClient1.contains("cti1"));
        assert(ctisOfClient1.contains("cti2"));
        assert(!ctisOfClient1.contains("cti3"));
        assert(!ctisOfClient1.contains("cti4"));
        assert(!ctisOfClient1.contains("cti5"));

        assert(!ctisOfClient2.contains("cti1"));
        assert(!ctisOfClient2.contains("cti2"));
        assert(ctisOfClient2.contains("cti3"));
        assert(ctisOfClient2.contains("cti4"));
        assert(ctisOfClient2.contains("cti5"));

        Set<String> peersOfCti9 = db.getPeers4Cti("cti9");
        assert(peersOfCti9.isEmpty());

        db.addCti2Peers("cti5", "client2", new HashSet<String>(){{add("rs1");}});
        Assert.fail("Duplicate Cti was added to DB");
    }

    /**
     * Tests for revocation methods
     *
     * @throws AceException
     */
    @Test (expected=AceException.class)
    public void testRevocation() throws AceException {
        db.addRevokedToken("cti1", "client1", new HashSet<String>(){{add("XXXrs1,rs2,rs3,rs4");}});
        db.addRevokedToken("cti2", "client1", new HashSet<String>(){{add("rs2,rs3XXX");}});
        db.addRevokedToken("cti3", "client2", new HashSet<String>(){{add("rs4,rs1");}});
        db.addRevokedToken("cti4", "client2", new HashSet<String>(){{add("rs1,rs2XXX,rs4");}});
        db.addRevokedToken("cti5", "client2", new HashSet<String>(){{add("rs1");}});

        Set<String> ctisOfRs1 = db.getPertainingTokens("rs1");
        Set<String> ctisOfRs2 = db.getPertainingTokens("rs2");
        Set<String> ctisOfRs3 = db.getPertainingTokens("rs3");
        Set<String> ctisOfRs4 = db.getPertainingTokens("rs4");
        Set<String> ctisOfRs5 = db.getPertainingTokens("rs5");
        Set<String> ctisOfclient1 = db.getPertainingTokens("client1");
        Set<String> ctisOfclient2 = db.getPertainingTokens("client2");

        assert(!ctisOfRs1.contains("cti1"));
        assert(!ctisOfRs1.contains("cti2"));
        assert(ctisOfRs1.contains("cti3"));
        assert(ctisOfRs1.contains("cti4"));
        assert(ctisOfRs1.contains("cti5"));

        assert(ctisOfRs2.contains("cti1"));
        assert(ctisOfRs2.contains("cti2"));
        assert(!ctisOfRs2.contains("cti3"));
        assert(!ctisOfRs2.contains("cti4"));
        assert(!ctisOfRs2.contains("cti5"));

        assert(ctisOfRs3.contains("cti1"));
        assert(!ctisOfRs3.contains("cti2"));
        assert(!ctisOfRs3.contains("cti3"));
        assert(!ctisOfRs3.contains("cti4"));
        assert(!ctisOfRs3.contains("cti5"));

        assert(ctisOfRs4.contains("cti1"));
        assert(!ctisOfRs4.contains("cti2"));
        assert(ctisOfRs4.contains("cti3"));
        assert(ctisOfRs4.contains("cti4"));
        assert(!ctisOfRs4.contains("cti5"));

        assert(!ctisOfRs5.contains("cti1"));
        assert(!ctisOfRs5.contains("cti2"));
        assert(!ctisOfRs5.contains("cti3"));
        assert(!ctisOfRs5.contains("cti4"));
        assert(!ctisOfRs5.contains("cti5"));

        assert(ctisOfclient1.contains("cti1"));
        assert(ctisOfclient1.contains("cti2"));
        assert(!ctisOfclient1.contains("cti3"));
        assert(!ctisOfclient1.contains("cti4"));
        assert(!ctisOfclient1.contains("cti5"));

        assert(!ctisOfclient2.contains("cti1"));
        assert(!ctisOfclient2.contains("cti2"));
        assert(ctisOfclient2.contains("cti3"));
        assert(ctisOfclient2.contains("cti4"));
        assert(ctisOfclient2.contains("cti5"));

        Set<String> peersOfCti1 = db.getPertainingPeers("cti1");
        Set<String> peersOfCti2 = db.getPertainingPeers("cti2");
        Set<String> peersOfCti3 = db.getPertainingPeers("cti3");
        Set<String> peersOfCti4 = db.getPertainingPeers("cti4");
        Set<String> peersOfCti5 = db.getPertainingPeers("cti5");

        assert(!peersOfCti1.contains("rs1"));
        assert(peersOfCti1.contains("rs2"));
        assert(peersOfCti1.contains("rs3"));
        assert(peersOfCti1.contains("rs4"));
        assert(peersOfCti1.contains("client1"));
        assert(!peersOfCti1.contains("client2"));

        assert(!peersOfCti2.contains("rs1"));
        assert(peersOfCti2.contains("rs2"));
        assert(!peersOfCti2.contains("rs3"));
        assert(!peersOfCti2.contains("rs4"));
        assert(peersOfCti2.contains("client1"));
        assert(!peersOfCti2.contains("client2"));

        assert(peersOfCti3.contains("rs1"));
        assert(!peersOfCti3.contains("rs2"));
        assert(!peersOfCti3.contains("rs3"));
        assert(peersOfCti3.contains("rs4"));
        assert(!peersOfCti3.contains("client1"));
        assert(peersOfCti3.contains("client2"));

        assert(peersOfCti4.contains("rs1"));
        assert(!peersOfCti4.contains("rs2"));
        assert(!peersOfCti4.contains("rs3"));
        assert(peersOfCti4.contains("rs4"));
        assert(!peersOfCti4.contains("client1"));
        assert(peersOfCti4.contains("client2"));

        assert(peersOfCti5.contains("rs1"));
        assert(!peersOfCti5.contains("rs2"));
        assert(!peersOfCti5.contains("rs3"));
        assert(!peersOfCti5.contains("rs4"));
        assert(!peersOfCti5.contains("client1"));
        assert(peersOfCti5.contains("client2"));


        db.deleteExpiredToken("cti1");
        db.deleteExpiredToken("cti2");
        db.deleteExpiredToken("cti3");
        db.deleteExpiredToken("cti4");
        //db.deleteExpiredToken("cti5");

        peersOfCti1 = db.getPertainingPeers("cti1");
        assert(peersOfCti1.isEmpty());

        //test primary key
        db.addRevokedToken("cti5", "client2", new HashSet<String>(){{add("rs1");}});
        Assert.fail("Duplicate Cti was added to DB");
    }

    /**
     * Test token hash table methods
     *
     * @throws AceException
     */
    @Test (expected=AceException.class)
    public void testTokenHash() throws Exception {

        db.addCti2TokenHash("cti1", "tokenHash1");
        db.addCti2TokenHash("cti2", "tokenHash2");
        db.addCti2TokenHash("cti3", "tokenHash3");

        Map<String, String> ctiToTokenHash = db.getTokenHashMap();;

        assert(ctiToTokenHash.containsKey("cti1"));
        assert(ctiToTokenHash.containsKey("cti2"));
        assert(ctiToTokenHash.containsKey("cti3"));

        db.addCti2TokenHash("cti1", "tokenHash4");
        Assert.fail("Duplicate Cti was added to DB");
    }

    /**
     * Tests for the Clients() method.
     *
     * @throws Exception
     */
    @Test
    public void testGetClients() throws Exception {
        Set<String> clients = db.getClients();
        assert(clients.contains("clientA"));
        assert(clients.contains("clientB"));
    }
    
    

}
