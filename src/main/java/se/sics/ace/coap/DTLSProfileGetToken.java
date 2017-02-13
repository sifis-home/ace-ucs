package se.sics.ace.coap;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;

/**
 * Implements getting a token for a client using the DTLS profile.
 * 
 * Clients are expected to create an instance of this class when the want to
 * perform token requests from a specific AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class DTLSProfileGetToken {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DTLSProfileGetToken.class.getName() ); 
    
    /**
     * The AS address.
     */
    String asAddr;
    
    /**
     * Constructor.
     * 
     * @param  asAddr  the address of the /token endpoint at the 
     *  Authorization Server (full URI including scheme, host and port if
     *  not default).
     */
    public DTLSProfileGetToken(String asAddr) {
        this.asAddr = asAddr;
    }

    /**
     * Sends a GET request to the /token endpoint of the AS.
     * For a symmetric key we will use the keyId as psk_identity.
     * 
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload.
     * @param key  the key to be used to secure the connection to the AS
     * 
     * @return  the payload of the response 
     * @throws IOException 
     * @throws CoseException 
     * @throws AceException 
     */
    public CBORObject getToken(CBORObject payload, OneKey key) 
            throws IOException, CoseException, AceException {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(0));
        CBORObject type = key.get(KeyKeys.KeyType);
        if (type.equals(KeyKeys.KeyType_Octet)) {
            String keyId = new String(key.get(KeyKeys.KeyId).GetByteString());
            builder.setPskStore(new StaticPskStore(
                    keyId, key.get(KeyKeys.Octet_K).GetByteString()));
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        } else if (type.equals(KeyKeys.KeyType_EC2)){
            builder.setIdentity(key.AsPrivateKey(), key.AsPublicKey());
            builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        } else {
            LOGGER.severe("Unknwon key type used for getting a token");
            throw new AceException("Unknown key type");
        }

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        dtlsConnector.start();
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        CoapClient client = new CoapClient(this.asAddr);
        client.setEndpoint(e);   
        CoapResponse response = client.post(
                payload.EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        return CBORObject.DecodeFromBytes(response.getPayload());
    }
}
