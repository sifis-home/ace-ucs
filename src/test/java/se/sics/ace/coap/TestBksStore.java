package se.sics.ace.coap;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assert;
/**
 * Tests for the Bouncy Castle Key Store backed implementation of 
 * Californium's PskStore Interface.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestBksStore {

    /**
     * The keystore used in the tests
     */
    private static BksStore keystore;
    
    /**
     * Sets up the Keystore
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     */
    @BeforeClass
    public static void setUp() throws KeyStoreException, 
            NoSuchProviderException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        BksStore.init("src/test/resources/testKeyStore.bks", "password", 
                "src/test/resources/add2id.cfg");
        keystore = new BksStore("src/test/resources/testKeyStore.bks", "password", 
                "src/test/resources/add2id.cfg");
    }
    
    /**
     * Delete the keystore and the mapping of addresses to ids.
     */
    @AfterClass
    public static void tearDown() {
        keystore = null;
        new File("src/test/resources/testKeyStore.bks").delete();
    }
    
    
    /**
     * Test successful call to addKey() and removeKey()
     * 
     * @throws Exception 
     */
    @Test
    public void testAddRemoveKeySuccess() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        assert(!keystore.hasKey("identity1"));
        keystore.addKey(key, "identity1", "password");
        assert(keystore.hasKey("identity1"));
        keystore.removeKey("identity1");
        assert(!keystore.hasKey("identity1"));
    }
    
    /**
     * Test unsuccessful call to removeKey() with identity = null
     * 
     * @throws Exception 
     */
    @Test (expected=KeyStoreException.class)
    public void testRemoveKeyFail() throws Exception {
        keystore.removeKey(null);
        Assert.fail("No exception thrown");
    }
    
    /**
     * Test unsuccessful call to addKey() with key = null
     * 
     * @throws Exception 
     */
    @Test (expected=KeyStoreException.class)
    public void testAddKeyFail() throws Exception {
        keystore.addKey(null, "identity1", "password");
        Assert.fail("No exception thrown");
    }
    
    
    /**
     * Test successful call to getKey()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeySuccess() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        keystore.addKey(key, "identity1", "password");
        keystore.setKeyPass("identity1", "password");
        byte[] key2 = keystore.getKey("identity1");
        Assert.assertArrayEquals(key, key2);
        keystore.removeKey("identity1");
    }
    
    /**
     * Test unsuccessful call to getKey() wrong password
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyFailPwd() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        keystore.addKey(key, "identity1", "password");
        keystore.setKeyPass("identity1", "wrongpassword");
        byte[] key2 = keystore.getKey("identity1");
        Assert.assertNull(key2);
        keystore.removeKey("identity1");
    }
    
    /**
     * Test unsuccessful call to getKey() wrong id
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyFailId() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        keystore.addKey(key, "identity1", "password");
        keystore.setKeyPass("identity1", "password");
        byte[] key2 = keystore.getKey("wrongidentity");
        Assert.assertNull(key2);
        keystore.removeKey("identity1");
    }
    
    
    /**
     * Test successful call to getIdentity()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetIdentitySuccess() throws Exception {
        String id = keystore.getIdentity(
                InetSocketAddress.createUnresolved("example.com", 5684));
        assert(id.equals("id1"));
        id = keystore.getIdentity(
                InetSocketAddress.createUnresolved("blah.se", 5684));
        assert(id.equals("id2"));
        id = keystore.getIdentity(
                InetSocketAddress.createUnresolved("blubb.de", 5684));
        assert(id.equals("id3"));
    }
    
    /**
     * Test unsuccessful call to getIdentity()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetIdentityFail() throws Exception {
        String id = keystore.getIdentity(
                InetSocketAddress.createUnresolved("404.com", 5684));
        Assert.assertNull(id);
    }
}
