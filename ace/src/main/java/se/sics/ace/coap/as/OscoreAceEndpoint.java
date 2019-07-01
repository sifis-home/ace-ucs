package se.sics.ace.coap.as;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.oscore.OSCoreResource;

import se.sics.ace.AceException;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.Token;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;

/**
 * This class implements the ACE endpoints/resources 
 * (OAuth lingo vs CoAP lingo) token and introspect for the OSCORE profile.
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoreAceEndpoint extends OSCoreResource implements AutoCloseable {

    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(OscoreAceEndpoint.class.getName());

    /**
     * The token library
     */
    private Endpoint e;

    /**
     * Constructor.
     * 
     * @param name  the resource name (should be "introspect" or "token")
     * @param e  the endpoint library instance
     */
    public OscoreAceEndpoint(String name, Endpoint e) {
        super(name, true);
        this.e = e;        
    }

    /**
     * Default constructor.
     * 
     * @param e  the endpoint library instance
     */
    public OscoreAceEndpoint(Introspect e) {
        super("introspect", true);
        this.e = e;
    }

    /**
     * Default constructor.
     * 
     * @param e  the endpoint library instance
     */
    public OscoreAceEndpoint(Token e) {
        super("token", true);
        this.e = e;
    }

    /**
     * Handles the POST request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handlePOST(CoapExchange exchange) {
        CoapReq req = null;
        try {
            req = CoapReq.getInstance(exchange.advanced().getRequest());
        } catch (AceException e) {//Message didn't have CBOR payload
            LOGGER.info(e.getMessage());
            exchange.respond(ResponseCode.BAD_REQUEST);
        }
        LOGGER.log(Level.FINEST, "Received request: " 
                + ((req==null)?"null" : req.toString()));
        //FIXME: Set sender Id
        
        
        Message m = this.e.processMessage(req);
        if (m instanceof CoapRes) {
            CoapRes res = (CoapRes)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res.toString());
            //XXX: Should the profile set the content format here?
            exchange.respond(res.getCode(), res.getRawPayload(), 
                    MediaTypeRegistry.APPLICATION_CBOR);
            return;
        }
        if (m == null) {//Wasn't a CoAP message
            return;
        }
        LOGGER.severe(this.e.getClass().getName() 
                + " library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
    }

    @Override
    public void close() throws Exception {
        this.e.close();
    }

}


