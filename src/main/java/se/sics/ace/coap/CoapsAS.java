package se.sics.ace.coap;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

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
     * 
     */
    public CoapsAS(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
            OneKey asymmetricKey) throws AceException {
        this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey());
        this.t = new Token(asId, pdp, db, time, asymmetricKey); 
    
        this.token = new CoapAceEndpoint(this.t);
        this.introspect = new CoapAceEndpoint(this.i);

        add(this.token);
        add(this.introspect);
        
        

        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
        builder.setClientAuthenticationRequired(true);
        builder.setPskStore(db);
        
        DTLSConnector connector = new DTLSConnector(builder.build(), null);

        for (InetAddress addr : 
            EndpointManager.getEndpointManager().getNetworkInterfaces()) {
            // only binds to IPv4 addresses and localhost
            if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
                CoapEndpoint endpoint = new CoapEndpoint(connector, 
                        NetworkConfig.getStandard()); 
                addEndpoint(endpoint);
                EndpointManager.getEndpointManager().setDefaultSecureEndpoint(endpoint);
            }
        }
    }

    @Override
    public void close() throws Exception {
       this.token.close();
       this.introspect.close();
    }
}
