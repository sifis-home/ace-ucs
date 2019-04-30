package org.eclipse.californium.oscore;

import java.security.Provider;
import java.security.Security;
import javax.xml.bind.DatatypeConverter;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;

/**
 * //TODO: Move/restructure
 * @author linuxwolf
 */
public abstract class InstallCryptoProviders {
    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final Provider EdDSA = new EdDSASecurityProvider();

    public static void installProvider() throws Exception {
        Security.insertProviderAt(PROVIDER, 1);
        Security.insertProviderAt(EdDSA, 0);
    }
    
    public static void uninstallProvider() throws Exception {
        Security.removeProvider(PROVIDER.getName());
        Security.removeProvider(EdDSA.getName());
    }
    
    //Rikard: Generate a key to be used for Countersignatures
    public static void generateCounterSignKey() throws CoseException {
    	OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
    	
    	//Print base64 encoded version with both public & private keys
    	byte[] keyObjectBytes = myKey.AsCBOR().EncodeToBytes();
    	String base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);
    	System.out.println("Public & Private: " + base64_encoded);
    	
    	//Print base64 encoded version with only public keys
    	keyObjectBytes = myKey.PublicKey().AsCBOR().EncodeToBytes();
    	base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);
    	System.out.println("Public only: " + base64_encoded);

    }
}
