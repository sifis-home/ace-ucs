package se.sics.ace.coap;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.rs.IntrospectionHandler;

/**
 * An introspection handler using CoAPS (i.e. CoAP over DTLS) to connect to an AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapsIntrospectionHandler implements IntrospectionHandler {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapsIntrospectionHandler.class.getName());
    
        /**
     * The CoAP client
     */
    private CoapClient client = null;
    
    /**
     * Constructor, builds a client that uses raw public keys.
     * 
     * @param rpk  the raw public key 
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * 
     */
    public CoapsIntrospectionHandler(OneKey rpk, String introspectAddress) 
            throws CoseException, IOException {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(0));
        builder.setIdentity(rpk.AsPrivateKey(), 
                rpk.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        dtlsConnector.start();
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
    }
    
    /**
     * Constructor, builds a client that uses pre-shared symmetric keys.
     * 
     * @param psk  the pre-shared key
     * @param pskIdentity  the identity associated to the pre-shared key
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * 
     */
    public CoapsIntrospectionHandler(byte[] psk, String pskIdentity,
            String introspectAddress) throws CoseException, IOException {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore(pskIdentity, psk));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        dtlsConnector.start();
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
    }
    
    @Override
    public Map<String, CBORObject> getParams(String tokenReference) 
            throws AceException {
        LOGGER.info("Sending introspection request on " + tokenReference);
        Map<String, CBORObject> params = new HashMap<>(); 
        params.put("access_token", CBORObject.FromObject(tokenReference));
        CoapResponse response =  this.client.post(
                Constants.abbreviate(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<String, CBORObject> map = Constants.unabbreviate(res);
        return map;
        
    }

}
