package se.sics.ace.as;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
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

import se.sics.ace.COSEparams;


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
    
    private static String dbPwd = null;
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws ASException 
     */
    @BeforeClass
    public static void setUp() throws SQLException, ASException {
        Scanner reader = new Scanner(System.in);  // Reading from System.in
        System.out.println("Please input DB password to run tests: ");
        dbPwd = reader.nextLine(); // Scans the next token of the input as an int.System.in.
        reader.close();
        
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), 
                p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam 
            = new ECKeyGenerationParameters(parameters, null);
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
        db.addClient("clientA", profiles, null, null, keyTypes, null,
                cnKeyPublicCompressed);
  
        profiles.clear();
        profiles.add("coap_oscoap");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "sensors", keyTypes, 
                key128, null);
        
        //Setup token entries
        String cid = "token1";
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000000L));   
        claims.put("cid", CBORObject.FromObject("token1"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(2000000L));
        claims.put("cid", CBORObject.FromObject("token2"));
        db.addToken(cid, claims);
        
        cid = "token2";
        claims.clear();
        claims.put("scope", CBORObject.FromObject("temp"));
        claims.put("aud",  CBORObject.FromObject("actuators"));
        claims.put("exp", CBORObject.FromObject(2000000L));
        claims.put("cid", CBORObject.FromObject("token2"));
        db.addToken(cid, claims);
    }
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws SQLException 
     * @throws ASException 
     */
    @AfterClass
    public static void tearDown() throws SQLException, ASException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        connectionProps.put("password", dbPwd);
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
    @Test (expected=ASException.class)
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
    @Test (expected=ASException.class)
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
        String profile = db.getSupportedProfile("sensors", "clientA");
        assert(profile.equals("coap_dtls"));
        
        profile = db.getSupportedProfile("sensors", "clientB");
        assert(profile == null);
    }
        
    /**
     * Test the getKeyTypes() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyTypes() throws Exception {
            
        String keyType = db.getSupportedPopKeyType("clientB", "rs1");
        assert(keyType.equals("PSK"));
        
        keyType =  db.getSupportedPopKeyType("clientB", "rs2");
        assert(keyType == null);
    }
    
    /**
     * Test the getTokenType() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetTokenType() throws Exception {
        Integer tokenType = db.getSupportedTokenType("sensors");
        assert(tokenType.equals(AccessTokenFactory.CWT_TYPE));
    }
    
    /**
     * Test the getCose() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCose() throws Exception {
        COSEparams cose = db.getSupportedCoseParams("actuators");
        assert(cose == null);
        
        cose = db.getSupportedCoseParams("sensors");
        assert(cose.toString().equals("997:-7:-6")); 
    }
    
    /**
     * Test the isScopeSupported() function. 
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
     * Test the getDefaultScope() function. 
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
     * Test the getDefaultAudience() function. 
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
     * Test the getRSS() function. 
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
     * Test the getExpTime() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetExpTime() throws Exception {
        long exp = db.getExpTime("rs1");
        assert(exp == 1000000L);
        
        exp =  db.getExpTime("rs2");
        assert(exp == 300000L);

    }

    /**
     * Test the getAudiences() function. 
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
     * Test the getRsPSK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsPSK() throws Exception {
       byte[] key = db.getRsPSK("rs1");
       Assert.assertArrayEquals(key128, key);
             
       key = db.getRsPSK("rs3");
       Assert.assertNull(key);
    }
    
    /**
     * Test the getRsRPK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetRsRPK() throws Exception {
        CBORObject rpk = db.getRsRPK("rs1");
        assert(rpk.equals(cnKeyPublicCompressed));
           
        rpk = db.getRsRPK("rs2");
        Assert.assertNull(rpk);
    }
    
    /**
     * Test the getCPSK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCPSK() throws Exception {
        byte[] key = db.getCPSK("clientB");
        Assert.assertArrayEquals(key128, key);
        
        key  = db.getCPSK("clientA");
        Assert.assertNull(key);
    }
    
    /**
     * Test the getCRPK() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testGetCRPK() throws Exception {
        CBORObject rpk = db.getCRPK("clientA");
        assert(rpk.equals(cnKeyPublicCompressed));

        rpk = db.getCRPK("clientB");
        Assert.assertNull(rpk);
    }

    /**
     * Test the deleteRS() function. 
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
        Set<Integer> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        Set<COSEparams> cose = new HashSet<>();      
        byte[] key = {0x00, 0x01};
        long expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, key, null);  
        
        
        Set<String> present = db.getAudiences("rs4");
        assert(present.contains("rs4"));
       
        db.deleteRS("rs4");
        present = db.getAudiences("rs4");
        assert(present.isEmpty());  
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
            
       byte[] newKey = db.getCPSK("clientC");
       Assert.assertArrayEquals(key, newKey);

       db.deleteClient("clientC");
       newKey = db.getCPSK("clientC");
       Assert.assertNull(newKey);
    }

    /**
     * Test the getClaims and deleteToken() functions. 
     * 
     * @throws Exception 
     */
    @Test
    public void testTokenTables() throws Exception {
        
        String cid = "token3";
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000000L));   
        claims.put("cid", CBORObject.FromObject("token3"));
        db.addToken(cid, claims);
                
        Map<String, CBORObject> result = db.getClaims(cid);
         
        //Checks that there are claims
        assert(!result.isEmpty());
                
        db.deleteToken(cid);
        result = db.getClaims(cid);
        assert(result.isEmpty());
    }
    
    /**
     * Test the purgeExpiredTokens() function. 
     * 
     * @throws Exception 
     */
    @Test
    public void testPurgeExpiredTokens() throws Exception {
        String cid = "token3";
        Map<String, CBORObject> claims = new HashMap<>();
        claims.put("scope", CBORObject.FromObject("co2"));
        claims.put("aud",  CBORObject.FromObject("sensors"));
        claims.put("exp", CBORObject.FromObject(1000L));   
        claims.put("cid", CBORObject.FromObject("token3"));
        db.addToken(cid, claims);
        
        db.purgeExpiredTokens(1001L);
       
        Map<String, CBORObject> result = db.getClaims(cid);
        assert(result.isEmpty());
    }
   
}
