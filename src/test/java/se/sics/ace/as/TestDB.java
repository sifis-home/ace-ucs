package se.sics.ace.as;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import se.sics.ace.AccessToken;
import se.sics.ace.COSEparams;
import se.sics.ace.ReferenceToken;
import se.sics.ace.cwt.CWT;

/**
 * Test the database connection classes.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDB {
  
    static CBORObject cnKeyPublic;
    static CBORObject cnKeyPublicCompressed;
    static ECPublicKeyParameters keyPublic;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    static SQLConnector db = null;
    
    /**
     * Set up tests.
     * @throws SQLException 
     */
    @BeforeClass
    public static void setUp() throws SQLException {
        
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);
        
        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();
        
        keyPublic = (ECPublicKeyParameters) p1.getPublic();
        
        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();

        cnKeyPublic = CBORObject.NewMap();
        cnKeyPublic.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cnKeyPublic.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cnKeyPublic.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublic.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        
        cnKeyPublicCompressed = CBORObject.NewMap();
        cnKeyPublicCompressed.Add(KeyKeys.KeyType.AsCBOR(), 
                    KeyKeys.KeyType_EC2);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Curve.AsCBOR(), 
                    KeyKeys.EC2_P256);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        
        db = new SQLConnector(null, null, null);
        //FIXME: hard-coded Root PWD
        db.init("ZzIbt3ELL34vEJITzaAIxT");
        
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
                expiration, key128, cnKeyPublicCompressed);
        
        profiles.remove("coap_oscoap");
        scopes.clear();
        auds.remove("actuators");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, key128, null);
        
        profiles.clear();
        profiles.add("coap_oscoap");
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
                expiration, null, cnKeyPublicCompressed);
        
        
        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("clientA", profiles, null, null, keyTypes, null, cnKeyPublicCompressed);
  
        profiles.clear();
        profiles.add("coap_oscoap");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "sensors", keyTypes, key128, null);
        
        //Setup token entries
        String cid = "token1";
        AccessToken token = new ReferenceToken();
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000000L));   
        claims.put("cid", CBORObject.FromObject("token1"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(2000000L));
        claims.put("cid", CBORObject.FromObject("token2"));
        token = new CWT(claims);
        db.addToken(cid, token, claims);
        
        cid = "token2";
        claims.clear();
        claims.put("scope", CBORObject.FromObject("temp"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(2000000L));
        claims.put("cid", CBORObject.FromObject("token2"));
        token = new CWT(claims);
        db.addToken(cid, token, claims);
    }
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws SQLException 
     */
    @AfterClass
    public static void tearDown() throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        //FIXME: hard-coded DB root password
        connectionProps.put("password", "ZzIbt3ELL34vEJITzaAIxT");
        Connection rootConn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306", connectionProps);
              
        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.close();
        rootConn.close();
        db.close();
    }
    
    
    /**
     * Test adding a RS that is already in the DB
     * (should fail)
     * 
     * @throws Exception 
     */
    @Test (expected=java.sql.SQLIntegrityConstraintViolationException.class)
    public void testAddDuplicateRS() throws Exception {
        Set<String> profiles = new HashSet<>();    
        Set<String> scopes = new HashSet<>();
        Set<String> auds = new HashSet<>();      
        Set<String> keyTypes = new HashSet<>();      
        Set<Integer> tokenTypes = new HashSet<>();
        Set<COSEparams> cose = new HashSet<>();        
        long expiration = 1000000L;
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, null, null);  
        Assert.fail("Duplicate RS was added to DB");
    }
    
    /**
     * Test adding a client that is already in the DB
     * (should fail)
     * 
     * @throws Exception 
     */
    @Test (expected=java.sql.SQLIntegrityConstraintViolationException.class)
    public void testAddDuplicateClient() throws Exception {
        Set<String> profiles = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        db.addClient("clientA", profiles, null, null, keyTypes, null, null);
        Assert.fail("Duplicate client was added to DB");
    }
    
     
    /**
     * Test the getProfiles() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetProfiles() throws Exception {
        
        
        ResultSet result = db.getProfiles("sensors", "clientA");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs1:coap_dtls");
        expectedResults.add("rs1:coap_oscoap");
        expectedResults.add("rs2:coap_dtls");
        expectedResults.add("clientA:coap_dtls");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            String id = result.getString(DBConnector.idColumn);
            String profile = result.getString(DBConnector.profileColumn);
            String r = id + ":" + profile;
            expectedResults.remove(r);            
        }  
        result.close();
        assert(expectedResults.isEmpty());
    }
        
    /**
     * Test the getKeyTypes() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyTypes() throws Exception {
            
        ResultSet result = db.getkeyTypes("rs1", "clientB");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs1:PSK");
        expectedResults.add("rs1:RPK");
        expectedResults.add("clientB:PSK");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            String id = result.getString(DBConnector.idColumn);
            String keyType = result.getString(DBConnector.keyTypeColumn);
            String r = id + ":" + keyType;
            expectedResults.remove(r);
        }        
        result.close();
        assert(expectedResults.isEmpty());
    }
    
    /**
     * Test the getGetScopes() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetScopes() throws Exception {
        ResultSet result = db.getScopes("actuators");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs1:temp");
        expectedResults.add("rs1:co2");
        expectedResults.add("rs3:co2");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            String id = result.getString(DBConnector.rsIdColumn);
            String scope = result.getString(DBConnector.scopeColumn);
            String r = id + ":" + scope;
            expectedResults.remove(r);
        }        
        result.close();
        assert(expectedResults.isEmpty());   
    }
    
    /**
     * Test the getTokenType() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetTokenType() throws Exception {
        ResultSet result = db.getTokenType("sensors");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs1:CWT");
        expectedResults.add("rs1:REF");
        expectedResults.add("rs2:CWT");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            String id = result.getString(DBConnector.rsIdColumn);
            String tokenType = result.getString(DBConnector.tokenTypeColumn);
            String r = id + ":" + tokenType;
            expectedResults.remove(r);
        }        
        result.close();
        assert(expectedResults.isEmpty());   
    }
    
    /**
     * Test the getCose() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCose() throws Exception {
        ResultSet result = db.getCose("actuators");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs3:996:5:-6");
        expectedResults.add("rs1:997:-7:-6");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            String id = result.getString(DBConnector.rsIdColumn);
            String cose = result.getString(DBConnector.coseColumn);
            String r = id + ":" + cose;
            expectedResults.remove(r);
        }        
        result.close();
        assert(expectedResults.isEmpty());   
    }
         
    /**
     * Test the getRSS() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRSS() throws Exception {
        ResultSet result = db.getRSS("actuators");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs3");
        expectedResults.add("rs1");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            expectedResults.remove(result.getString(DBConnector.rsIdColumn));
        }
        result.close();
        assert(expectedResults.isEmpty());    
    }
  
    /**
     * Test the getAudiences() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetAudiences() throws Exception {
        ResultSet result = db.getAudiences("rs1");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("actuators");
        expectedResults.add("sensors");
        expectedResults.add("rs1");
        while (result.next()) {
            assert(!expectedResults.isEmpty());
            expectedResults.remove(result.getString(DBConnector.audColumn));
        }
        result.close();
        assert(expectedResults.isEmpty());    
    }
    
    /**
     * Test the getExpTime() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetExpTime() throws Exception {
        ResultSet result = db.getExpTime("rs1");
        while (result.next()) {
            assert(result.getLong(DBConnector.expColumn) == 1000000L);
        }
        result.close();
        result = db.getExpTime("rs2");
        while (result.next()) {
            assert(result.getLong(DBConnector.expColumn) == 300000L);
        }
        result.close();
    }

    /**
     * Test the getRsPSK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsPSK() throws Exception {
        ResultSet result = db.getRsPSK("rs1");
        while (result.next()) {
            byte[] key = result.getBytes(DBConnector.pskColumn);
            Assert.assertArrayEquals(key128, key);
        }
        result.close();
        
        result = db.getRsPSK("rs3");
        result.next();
        result.getObject(DBConnector.pskColumn);
        assert(result.wasNull());
        result.close();
    }
    
    /**
     * Test the getRsRPK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsRPK() throws Exception {
        ResultSet result = db.getRsRPK("rs1");
        while (result.next()) {
            byte[] rawRPK = result.getBytes(DBConnector.rpkColumn);
            CBORObject rpk = CBORObject.DecodeFromBytes(rawRPK);
            assert(rpk.equals(cnKeyPublicCompressed));
        }
        result.close();
        
        result = db.getRsRPK("rs2");
        result.next();
        result.getObject(DBConnector.rpkColumn);
        assert(result.wasNull());
        result.close();
    }
    
    /**
     * Test the getCPSK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCPSK() throws Exception {
        ResultSet result = db.getCPSK("clientB");
        while (result.next()) {
            byte[] key = result.getBytes(DBConnector.pskColumn);
            Assert.assertArrayEquals(key128, key);
        }
        result.close();
        
        result = db.getCPSK("clientA");
        result.next();
        result.getObject(DBConnector.pskColumn);
        assert(result.wasNull());
        result.close();
    }
    
    /**
     * Test the getCRPK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCRPK() throws Exception {
        ResultSet result = db.getCRPK("clientA");
        while (result.next()) {
            byte[] rawRPK = result.getBytes(DBConnector.rpkColumn);
            CBORObject rpk = CBORObject.DecodeFromBytes(rawRPK);
            assert(rpk.equals(cnKeyPublicCompressed));
        }
        result.close();
        
        result = db.getCRPK("clientB");
        result.next();
        result.getObject(DBConnector.rpkColumn);
        assert(result.wasNull());
        result.close();
    }

    /**
     * Test the getDefaultScope() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetDefaultScope() throws Exception {
        ResultSet result = db.getDefaultScope("clientB");
        while (result.next()) {
            assert(result.getString(DBConnector.defaultScope).equals("co2"));
        }
        result.close();
        
        result = db.getDefaultScope("clientA");
        result.next();
        result.getObject(DBConnector.defaultScope);
        assert(result.wasNull());
        result.close();
    }
    
    /**
     * Test the getDefaultAudience() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetDefaultAudience() throws Exception {
        ResultSet result = db.getDefaultAudience("clientB");
        while (result.next()) {
            assert(result.getString(DBConnector.defaultAud).equals("sensors"));
        }
        result.close();
        
        result = db.getDefaultAudience("clientA");
        result.next();
        result.getObject(DBConnector.defaultAud);
        assert(result.wasNull());
        result.close();
    }

    /**
     * Test the deleteRS() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testDeleteRS() throws Exception {
        Set<String> profiles = new HashSet<>();    
        Set<String> scopes = new HashSet<>();
        Set<String> auds = new HashSet<>();      
        Set<String> keyTypes = new HashSet<>();      
        Set<Integer> tokenTypes = new HashSet<>();
        Set<COSEparams> cose = new HashSet<>();        
        long expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, null, null);  
        
        
        ResultSet result = db.getAudiences("rs4");
        while (result.next()) {
            assert(result.getString(DBConnector.audColumn).equals("rs4"));
        }
        result.close();
        
        result = db.getRsPSK("rs4");
        result.next();
        result.getObject(DBConnector.pskColumn);
        assert(result.wasNull());
        result.close();
        
        db.deleteRS("rs4");
        result = db.getAudiences("rs4");
        assert(!result.next());
        result.close();
        
        result = db.getRsRPK("rs4");
        assert(!result.next());
        result.close();
        
    }

    /**
     * Test the deleteClient() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testDeleteClient() throws Exception {
        Set<String> profiles = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        byte[] key = {0x00, 0x01};
        db.addClient("clientC", profiles, null, null, keyTypes, key, null);
            
        ResultSet result = db.getCPSK("clientC");
        while (result.next()) {
            byte[] foo = result.getBytes(DBConnector.pskColumn);
            Assert.assertArrayEquals(key, foo);
        }
        result.close();
               
        db.deleteClient("clientC");
        result = db.getCPSK("clientC");
        assert(!result.next());
        result.close();
    }

    /**
     * Test the getToken(), getClaims and deleteToken() functions. 
     * 
     * @throws Exception 
     */
    @Test
    public void testTokenTables() throws Exception {
        
        String cid = "token3";
        AccessToken token = new ReferenceToken();
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000000L));   
        claims.put("cid", CBORObject.FromObject("token3"));

        db.addToken(cid, token, claims);
        
        ResultSet result = db.getClaims(cid);
         
        //Checks that there are claims
        assert(result.next());
        result.close();
        
        result = db.getToken(cid);
        assert(result.next());
        byte[] bar = result.getBytes(DBConnector.tokenColumn);
        Assert.assertArrayEquals(token.encode().EncodeToBytes(), bar);
        result.close();
        
        db.deleteToken(cid);
        result = db.getClaims(cid);
        assert(!result.next());
        result.close();
        
        result = db.getToken(cid);
        assert(!result.next());   
        result.close();
    }
    
    /**
     * Test the purgeExpiredTokens() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testPurgeExpiredTokens() throws Exception {
        String cid = "token3";
        AccessToken token = new ReferenceToken();
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000L));   
        claims.put("cid", CBORObject.FromObject("token3"));
        db.addToken(cid, token, claims);
        
        db.purgeExpiredTokens(1001L);
       
        ResultSet result = db.getClaims(cid);
        assert(!result.next());
        result.close();
        
        result = db.getToken(cid);
        assert(!result.next());
        result.close();
    }
   
}
