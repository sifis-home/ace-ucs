package se.sics.ace.coap;

import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.PDP;
import se.sics.ace.as.Token;

/**
 * An authorization server listening to CoAP requests
 * over DTLS.
 * 
 * Create an instance of this server with the constructor then call
 * CoapsAS.start();
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapsAS extends CoapServer implements AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapsAS.class.getName());

    /**
     * The token endpoint
     */
    Token t = null;
    
    /**
     * The introspect endpoint
     */
    Introspect i = null;

    private CoapAceEndpoint token;

    private CoapAceEndpoint introspect;

    
    /**
     * Constructor.
     * 
     * @param asId 
     * @param db 
     * @param pdp 
     * @param time 
     * @param asymmetricKey 
     * @throws AceException 
     * @throws CoseException 
     * 
     */
    public CoapsAS(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
            OneKey asymmetricKey) throws AceException, CoseException {
        if (asymmetricKey == null) {
            this.i = new Introspect(pdp, db, time, null);
        } else {
            this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey());
        }
        this.t = new Token(asId, pdp, db, time, asymmetricKey); 
    
        this.token = new CoapAceEndpoint(this.t);
        this.introspect = new CoapAceEndpoint(this.i);

        add(this.token);
        add(this.introspect);

       DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(
               new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
       if (asymmetricKey != null && 
               asymmetricKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2 ) {
           LOGGER.info("Starting CoapsAS with PSK and RPK");
           config.setSupportedCipherSuites(new CipherSuite[]{
                   CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
       } else {
           LOGGER.info("Starting CoapsAS with PSK only");
           config.setSupportedCipherSuites(new CipherSuite[]{
                   CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
       }
       config.setPskStore(db);
       if (asymmetricKey != null) {
           config.setIdentity(asymmetricKey.AsPrivateKey(), 
                   asymmetricKey.AsPublicKey());
       }
      
       DTLSConnector connector = new DTLSConnector(config.build());
       addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
    }

    @Override
    public void close() throws Exception {
       LOGGER.info("Closing down CoapsAS ...");
       this.token.close();
       this.introspect.close();
    }
}
