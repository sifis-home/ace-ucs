package se.sics.ace.coap.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
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
 * Implements getting a token from the /token endpoint for a client 
 * using the DTLS profile.
 * 
 * Also implements POSTing the token to the /authz-info endpoint at the 
 * RS.
 * 
 * Clients are expected to create an instance of this class when the want to
 * perform token requests from a specific AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class DTLSProfileRequests {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DTLSProfileRequests.class.getName() ); 

    /**
     * Sends a POST request to the /token endpoint of the AS to request an
     * access token. If the DTLS connection uses pre-shared symmetric keys 
     * we will use the key identifier (COSE kid) as psk_identity.
     * 
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param key  the key to be used to secure the connection to the AS. 
     *  This MUST have a kid.
     * 
     * @return  the payload of the response 
     *
     * @throws AceException 
     */
    public static CBORObject getToken(String asAddr, CBORObject payload, OneKey key) 
            throws AceException {
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
            try {
                builder.setIdentity(key.AsPrivateKey(), key.AsPublicKey());
            } catch (CoseException e) {
                LOGGER.severe("Failed to transform key: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
            builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        } else {
            LOGGER.severe("Unknwon key type used for getting a token");
            throw new AceException("Unknown key type");
        }

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        try {
            dtlsConnector.start();
        } catch (IOException e) {
            LOGGER.severe("Failed to start DTLSConnector: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        CoapClient client = new CoapClient(asAddr);
        client.setEndpoint(e);   
        CoapResponse response = client.post(
                payload.EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        return CBORObject.DecodeFromBytes(response.getPayload());
    }
    
    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token.
     * 
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param useDTLS  use DTLS without client authentication to transfer 
     *  the token or use plain CoAP. Note that this does NOT work with pre-shared
     *  keys or with an RS that requires client authentication
     * 
     * @return  the payload of the response 
     *
     * @throws AceException 
     */
    public static CBORObject postToken(String asAddr, CBORObject payload, boolean useDTLS) 
            throws AceException {
        Connector c = null;
        if (useDTLS) {
            DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                    new InetSocketAddress(0));
            builder.setClientOnly();
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
            c = new DTLSConnector(builder.build());
            try {
                c.start();
            } catch (IOException e) {
                LOGGER.severe("Failed to start DTLSConnector: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
        } else {
            c = new UDPConnector(); 
        }
        CoapEndpoint e = new CoapEndpoint(c, NetworkConfig.getStandard());
        CoapClient client = new CoapClient(asAddr);
        client.setEndpoint(e);   
        CoapResponse response = client.post(
                payload.EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        return CBORObject.DecodeFromBytes(response.getPayload());
    }
}
