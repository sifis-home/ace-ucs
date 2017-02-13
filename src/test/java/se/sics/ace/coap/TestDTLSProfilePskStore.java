package se.sics.ace.coap;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
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
import se.sics.ace.Constants;
import se.sics.ace.coap.rs.DTLSProfilePskStore;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfilePskStore class that implements fetching the access token from the
 * psk-identity in the DTLS handshake.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDTLSProfilePskStore {

    private static DTLSProfilePskStore store = null;
   
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static AuthzInfo ai;

    private static TokenRepository tr;
    
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() throws AceException, IOException {
        
        
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
       
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        tr = new TokenRepository(valid, resources, 
                "src/test/resources/tokens.json", ctx);
        
        ai = new AuthzInfo(tr, 
                Collections.singletonList("TestAS"), new KissTime(), null, 
                valid, ctx);
        store = new DTLSProfilePskStore(ai);
    }
    
    /**
     * Deletes the test file after the tests
     * 
     * @throws SQLException 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException  {
        tr.close();
        ai.close();
        new File("src/test/resources/tokens.json").delete();
    }  
    
    
    /**
     * Test with an invalid psk-identity (non-parseable)
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidPskId() throws Exception {
        byte[] key = store.getKey("blah");
        Assert.assertNull(key);
    }
    
    /**
     * Test with an invalid token in the psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidToken() throws Exception {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        params.put("cnf", key.AsCBOR());
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject cbor = token.encode(ctx);
        String psk_identity = Base64.getEncoder().encodeToString(
                cbor.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertNull(psk);
    }

    /**
     * Test with an valid psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskId() throws Exception {
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("scope", CBORObject.FromObject("r_temp"));
        params.put("aud", CBORObject.FromObject("rs1"));
        params.put("cti", CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put("iss", CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        params.put("cnf", key.AsCBOR());
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject cbor = token.encode(ctx);
        String psk_identity = Base64.getEncoder().encodeToString(
                cbor.EncodeToBytes()); 

        byte[] psk = store.getKey(psk_identity);
        Assert.assertArrayEquals(key128 ,psk);
    }
}