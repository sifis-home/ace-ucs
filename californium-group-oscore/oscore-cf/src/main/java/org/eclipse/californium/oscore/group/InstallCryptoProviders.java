package org.eclipse.californium.oscore.group;

import java.security.Provider;
import java.security.Security;
import java.util.Base64;

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

    public static void installProvider() {
        Security.insertProviderAt(PROVIDER, 1);
        Security.insertProviderAt(EdDSA, 0);
    }
    
    public static void uninstallProvider() {
        Security.removeProvider(PROVIDER.getName());
        Security.removeProvider(EdDSA.getName());
    }
    
    //Rikard: Generate a key to be used for Countersignatures
	public static void generateCounterSignKey(AlgorithmID alg) throws CoseException {
		OneKey myKey = OneKey.generateKey(alg);
    	
    	//Print base64 encoded version with both public & private keys
    	byte[] keyObjectBytes = myKey.AsCBOR().EncodeToBytes();
    	String base64_encoded = Base64.getEncoder().encodeToString(keyObjectBytes);
    	System.out.println("Public & Private: " + base64_encoded);
    	
    	//Print base64 encoded version with only public keys
    	keyObjectBytes = myKey.PublicKey().AsCBOR().EncodeToBytes();
    	base64_encoded = Base64.getEncoder().encodeToString(keyObjectBytes);
    	System.out.println("Public only: " + base64_encoded);

    }
    
	// Rikard: Generate a key to be used for EDDSA Countersignatures
	public static void generateCounterSignKey() throws CoseException {
		generateCounterSignKey(AlgorithmID.EDDSA);

	}

    //Rikard: Return a key to be used for Countersignatures
    public static String getCounterSignKey() throws CoseException {
    	OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
    	byte[] keyObjectBytes = myKey.AsCBOR().EncodeToBytes();
    	String base64_encoded = Base64.getEncoder().encodeToString(keyObjectBytes);
    	
    	return base64_encoded;

    }
}
