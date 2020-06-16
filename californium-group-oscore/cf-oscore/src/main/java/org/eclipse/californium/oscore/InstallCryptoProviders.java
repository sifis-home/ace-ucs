package org.eclipse.californium.oscore;

import java.security.Provider;
import java.security.Security;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Base64;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class InstallCryptoProviders {

	private static final Provider EdDSA = new EdDSASecurityProvider();

	public static void installProvider() {
		Security.insertProviderAt(EdDSA, 0);
	}

	// Rikard: Return a key to be used for Countersignatures
	public static String getCounterSignKey() throws CoseException {
		OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
		byte[] keyObjectBytes = myKey.AsCBOR().EncodeToBytes();
		String base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);

		return base64_encoded;

	}
}
