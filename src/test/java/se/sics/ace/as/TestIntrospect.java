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

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
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
        
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        
        ECDomainParameters parameters = new ECDomainParameters(
                p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam 
            = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);
        
        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();
        
        ECPublicKeyParameters keyPublic = (ECPublicKeyParameters) p1.getPublic();
        ECPrivateKeyParameters keyPrivate = (ECPrivateKeyParameters) p1.getPrivate();
        
        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        byte[] rgbD = keyPrivate.getD().toByteArray();      
        
        CBORObject cKeyPublic = CBORObject.NewMap();
        cKeyPublic.Add(KeyKeys.KeyType.AsCBOR(), 
                    KeyKeys.KeyType_EC2);
        cKeyPublic.Add(KeyKeys.EC2_Curve.AsCBOR(), 
                    KeyKeys.EC2_P256);
        cKeyPublic.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cKeyPublic.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        publicKey = new OneKey(cKeyPublic);
        
        CBORObject cKeyPrivate = CBORObject.NewMap();
        cKeyPrivate.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cKeyPrivate.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cKeyPrivate.Add(KeyKeys.EC2_D.AsCBOR(), rgbD);
        privateKey = new OneKey(cKeyPrivate);
        
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
        
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
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
                new Testmessage(-1, "unauthorizedRS", CBORObject.Null));
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
                new Testmessage(-1, "rs1", nullObj));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add("error", "must provide non-null token");
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
        CBORObject purged = CBORObject.FromObject("token1");
        Message response = i.processMessage(
                new Testmessage(-1, "rs1", purged));
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
        Message response = i.processMessage(
                new Testmessage(-1, "rs1", notExist));
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
        Message response = i.processMessage(
                new Testmessage(-1, "rs1", token.encode(ctx)));
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
        Message response = i.processMessage(
                new Testmessage(-1, "rs1", t.encode()));
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject rparams = CBORObject.DecodeFromBytes(
                response.getRawPayload());
        Constants.unabbreviate(rparams);
        System.out.println(rparams.toString());
        assert(rparams.get("active").equals(CBORObject.True));
    }
}
