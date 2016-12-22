package se.sics.ace.coap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * A PskStore implementation based on BKS.
 * 
 * This will retrieve keys from a BKS keystore.
 * 
 * FIXME: Needs Junit tests
 * 
 * @author Ludwig Seitz
 *
 */
public class BksStore implements PskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(BksStore.class.getName());

    /**
     * The underlying JCEKS keystore
     */
    private KeyStore keystore = null;
    
    /**
     * The temporary variable to store a key password
     */
    private String keyPwd = null;
    
    /**
     * The temporary variable to store a key identity
     */
    private String keyId = null;
    
    /**
     * The in-memory map of addresses to identities
     */
    private Map<InetSocketAddress, String> addr2id = new HashMap<>();
    
    static {
        Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    /**
     * Constructor.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws NoSuchProviderException 
     */
    public BksStore(String keystoreLocation, String keystorePwd, String addr2idFile) 
            throws NoSuchAlgorithmException, CertificateException, 
            IOException, KeyStoreException, NoSuchProviderException {

        InputStream keystoreStream = new FileInputStream(keystoreLocation);
        this.keystore = KeyStore.getInstance("BKS", "BC");
        this.keystore.load(keystoreStream, keystorePwd.toCharArray());
        keystoreStream.close();   
        BufferedReader in = new BufferedReader(new FileReader(addr2idFile));
        String line = "";
        while ((line = in.readLine()) != null) {
            String parts[] = line.split(":");
            this.addr2id.put(InetSocketAddress.createUnresolved(parts[0].trim(), 
                    Integer.parseInt(parts[1])), parts[2].trim());
        }
        in.close();
    }
    
    /**
     * Create the initial keystore and address2identity mapping file.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public static void init(String keystoreLocation, String keystorePwd,
            String addr2idFile) throws KeyStoreException, 
            NoSuchProviderException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, keystorePwd.toCharArray());
        FileOutputStream fo = new FileOutputStream(keystoreLocation);
        keyStore.store(fo, keystorePwd.toCharArray());
        fo.close();   
        File file = new File(addr2idFile);
        file.createNewFile();        
    }
    
    
    /**
     * Set a key password for a certain key identity.
     * This method needs to be called before any calls to getKey() and
     * getIdentity().
     * 
     * @param identity  
     * @param keyPwd
     */
    public void setKeyPass(String identity, String keyPwd) {
        this.keyPwd = keyPwd;
        this.keyId = identity;
    }

    @Override
    public byte[] getKey(String identity) {
        if (this.keyPwd == null || this.keyId == null) {
            return null;
        }
        try {
            if (!this.keystore.containsAlias(identity)) {
                return null;
            }
        } catch (KeyStoreException e) {
            LOGGER.severe(e.getMessage());
            return null;
        }

        Key key;
        try {
            key = this.keystore.getKey(identity, this.keyPwd.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException
                | NoSuchAlgorithmException e) {
            LOGGER.severe(e.getMessage());
            return null;
        }
        return key.getEncoded();
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        return this.addr2id.get(inetAddress);
                
    }

}
