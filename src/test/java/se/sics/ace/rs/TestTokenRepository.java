package se.sics.ace.rs;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

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
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
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
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr; 
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
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
               
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes());
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        CBORObject otherKeyData = CBORObject.NewMap();
        otherKeyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        otherKeyData.Add(KeyKeys.KeyId.AsCBOR(), "otherKey".getBytes());
        otherKeyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(otherKeyData);
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<String>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
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
     * Test add token without scope
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoScope() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no scope");
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token without cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCti() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no cti");
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token with invalid cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCti() throws AceException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        params.put("cti", CBORObject.FromObject("token1"));
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Cti has invalid format");
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token with duplicate cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenDuplicateCti() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Duplicate cti");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", symmetricKey.AsCBOR());
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        tr.addToken(params, ctx);
        
        params.clear();
        params.put("scope", CBORObject.FromObject("r_co2"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cnf", asymmetricKey.PublicKey().AsCBOR());
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token without cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no cnf");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token with unknown kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenUnknownKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token refers to unknown kid");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("kid", CBORObject.FromObject("blah".getBytes()));
        params.put("cnf", cnf);
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token with invalid cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Invalid cnf element:");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("kid", CBORObject.FromObject("blah".getBytes()));
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes()));
        params.put("cnf", cnf);
        tr.addToken(params, ctx);
    }
    
    /**
     * Test add token with invalid Encrypt0
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenCnfInvalidEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Error while decrypting a cnf claim");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        Encrypt0Message cnf = new Encrypt0Message();
        cnf.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
                Attribute.PROTECTED);
        cnf.SetContent(symmetricKey.EncodeToBytes());
        cnf.encrypt(key128a);
        
        params.put("cnf", cnf.EncodeToCBORObject());
        tr.addToken(params, ctx);
    }
    
    
    /**
     * Test add token with cnf without kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Cnf claim is missing kid");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes()));
        params.put("cnf", cnf);
        tr.addToken(params, ctx);
    }
    
    
    /**
     * Test add token with cnf with invalid kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("cnf contains invalid kid");
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("kid", CBORObject.FromObject("blah"));
        params.put("cnf", cnf);
        tr.addToken(params, ctx);
    }
    
    
    
    /**
     * Test add token with cnf containing COSE_Key
     *
     * @throws AceException 
     */
    @Test
    public void testTokenCnfCoseKey() throws AceException {
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
        
        Assert.assertTrue(tr.canAccess("rpk", null, "co2", "GET", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("rpk", null, "co2", "POST", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("ourKey", null, "co2", "POST", new KissTime(), null));
        Assert.assertTrue(tr.canAccess("ourKey", null, "temp", "GET", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("otherKey", null, "temp", "GET", new KissTime(), null));
    }
    
    
    /**
     * Test add token with cnf containing known kid
     *
     * @throws AceException 
     */
    @Test
    public void testTokenCnfKid() throws AceException {
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
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("kid", CBORObject.FromObject("ourKey".getBytes()));
        params.put("cnf", cnf);
        tr.addToken(params, ctx);
        
        
        Assert.assertTrue(tr.canAccess("ourKey", null, "co2", "GET", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("rpk", null, "co2", "POST", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("rpk", null, "co2", "POST", new KissTime(), null));
        Assert.assertTrue(tr.canAccess("ourKey", null, "temp", "GET", new KissTime(), null));
        Assert.assertFalse(tr.canAccess("otherKey", null, "temp", "GET", new KissTime(), null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenCnfEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("iss", CBORObject.FromObject("TestAS"));
        params.put("cti", CBORObject.FromObject("token1".getBytes()));
        Encrypt0Message cnf = new Encrypt0Message();
        cnf.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
                Attribute.PROTECTED);
        cnf.SetContent(symmetricKey.EncodeToBytes());
        cnf.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());        
        params.put("cnf", cnf.EncodeToCBORObject());
        tr.addToken(params, ctx);
       //FIXME: Assert something
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
    
    
    /**
     * Remove lingering token1 entries
     * @throws AceException 
     */
    @After
    public void cleanup() throws AceException {
        tr.removeToken(CBORObject.FromObject("token1".getBytes()));
        tr.removeToken(CBORObject.FromObject("token2".getBytes()));
    }
    
}
