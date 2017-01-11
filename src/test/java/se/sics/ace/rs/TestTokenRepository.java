package se.sics.ace.rs;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
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
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissValidator;

/**
 * Tests for the TokenRepository class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestTokenRepository {
    
    static OneKey asymmetricKey;
    static OneKey symmetricKey;
    static OneKey otherKey;
    static CwtCryptoCtx ctx;

    private static TokenRepository tr; 
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() 
            throws AceException, CoseException, IOException {

        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        asymmetricKey.add(KeyKeys.KeyId, CBORObject.FromObject("rpk".getBytes()));
        
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes());
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        keyData.Remove(KeyKeys.KeyId.AsCBOR());
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "otherKey".getBytes());
        keyData.Remove(KeyKeys.Octet_K.AsCBOR());
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(keyData);
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        myResource.clear();
        myResource.put("co2", actions);
        myScopes.put("r_co2", myResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        Set<String> resources = new HashSet<>();
        resources.add("temp");
        resources.add("co2");
        tr = new TokenRepository(valid, resources, 
                "src/test/resources/tokens.json", null);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
       
    }
    
    /**
     * Deletes the test file after the tests
     * 
     * @throws SQLException 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws SQLException, AceException {
        new File("src/test/resources/tokens.json").delete();
    }
    
    /**
     * Test add and remove resources
     *
     * @throws AceException 
     */
    @Test
    public void testResource() throws AceException {
        Assert.assertTrue(tr.inScope("r_co2"));
        tr.removeResource("co2");
        Assert.assertFalse(tr.inScope("r_co2"));
        tr.addResource("co2");
        Assert.assertTrue(tr.inScope("r_co2")); 
    }
    
    /**
     * Test add and remove tokens
     *
     * @throws AceException 
     */
    @Test
    public void testToken() throws AceException {
        
        //Test token without scope
        
        //Test token without cti
        
        //Test token with invalid cti format (integer)
        
        //Test token with duplicate cti
        
        //Test token without cnf
        
        //Test token with only kid referring to unknown kid
        
        //Test token with invalid cnf element
        
        //Test token with Encrypt0 but false key
        
        //Test token with only kid referring to known kid
        
        //Test token with cnf containing a COSE_Key
        
        //Test token with cnf containing a Encrypt0 containing a
        //COSE_Key
        
        //Test token with cnf element not containing a kid
        
        //Test token with cnf element containing a kid 
        //that is not a bytestring
        
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        tr.addToken(params, ctx);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject("token2".getBytes()));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", asymmetricKey.PublicKey().AsCBOR());
        tr.addToken(params, ctx);
    }
    
    /**
     * Test pollTokens()
     *
     * @throws AceException 
     */
    @Test
    public void testPollToken() throws AceException {
        //TODO:
    }
    
    /**
     * Test canAccess()
     *
     * @throws AceException 
     */
    @Test
    public void testCanAccess() throws AceException {
        //TODO:
    }
    
    /**
     * Test inScope()
     *
     * @throws AceException 
     */
    @Test
    public void testInScope() throws AceException {
        Assert.assertTrue(tr.inScope("r_co2"));
        Assert.assertTrue(tr.inScope("r_temp"));
        Assert.assertFalse(tr.inScope("w_temp"));
        Assert.assertFalse(tr.inScope("rs1"));
        Assert.assertFalse(tr.inScope("temp"));
    }
    
    /**
     * Test getPoP()
     *
     * @throws AceException 
     */
    @Test
    public void testGetPoP() throws AceException {
        //TODO:
    }
}
