package se.sics.ace.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;

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
import se.sics.ace.ReferenceToken;
import se.sics.ace.TestConfig;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.Introspect;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler4Tests;
import se.sics.ace.rs.TokenRepository;

/**
 * Tests the client side of the client token code.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestClientToken {
    
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static DBConnector db = null;
    
    private static String dbPwd = null;
    
    private static AuthzInfo ai = null;
    private static Introspect i; 
    private static TokenRepository tr = null;
    
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
        
        //Just to be sure no old test pollutes the DB
        SQLConnector.wipeDatabase(dbPwd);
        
        SQLConnector.createUser(dbPwd, "aceuser", "password", 
                "jdbc:mysql://localhost:3306");
        SQLConnector.createDB(dbPwd, "aceuser", "password", null,
                "jdbc:mysql://localhost:3306");

     
        
        OneKey k_c_as = new OneKey();
        k_c_as.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        k_c_as.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        k_c_as.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
       
        OneKey k_cnf = new OneKey();
        k_cnf.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        k_cnf.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x11, 0x34}));
        k_cnf.add(KeyKeys.Octet_K, CBORObject.FromObject(key128a));
        
        db = SQLConnector.getInstance(null, null, null);
        
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client", profiles, null, null, keyTypes, k_c_as, 
                null, true);
       
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
                
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        createTR(valid);
        tr = TokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128a, 
                coseP.getAlg().AsCBOR());
        i = new Introspect(
                KissPDP.getInstance(TestConfig.testFilePath + "acl.json", db),
                db, new KissTime(), null);
        ai = new AuthzInfo(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                new IntrospectionHandler4Tests(i, "rs1", "TestAS"),
                valid, ctx);
        
        //Set up token for introspection
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, k_cnf.AsCBOR());
        params.put(Constants.CNF, cbor);
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x08}), params);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});
        db.addCti2Client(ctiStr, "client");

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
                    + "tokens.json", null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    } 
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws SQLException 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws SQLException, AceException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306", connectionProps);
              
        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        String dropUser = "DROP USER 'aceuser'@'localhost';";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);        
        stmt.close();
        rootConn.close();
        db.close();
        i.close();
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }

    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testClientToken() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        
        //Do the introspection manually, return the result
        ReferenceToken t = new ReferenceToken(new byte[]{0x08});
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.TOKEN, t.encode());
        Message response = i.processMessage(
                new LocalMessage(-1, "rs1", "TestAS", params));
        
        //Now process the returned client token
        Map<Short, CBORObject> claims 
            = GetToken.handleClientToken(response.getRawPayload(), key128);
        
        assert(claims.get(Constants.CNF) != null);
        CBORObject cnf = claims.get(Constants.CNF);
        OneKey key = new OneKey(cnf.get(Constants.COSE_KEY_CBOR));
        Assert.assertArrayEquals(key128a, 
                key.get(KeyKeys.Octet_K).GetByteString());
        assert(claims.get(Constants.PROFILE).equals(
                CBORObject.FromObject("coap_dtls")));
    }
        

}
