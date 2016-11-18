package se.sics.ace.rs;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * This class implements the authz-info endpoint / resource (OAuth lingo vs CoAP lingo).
 * 
 * @author Ludwig Seitz
 *
 */
public class CoAPAuthzInfo extends CoapResource {

    /**
     * @param name
     */
    public CoAPAuthzInfo(String name) {
        super(name);
        // TODO Auto-generated constructor stub
    }
    
    /**
     * Handles the POST request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handlePOST(CoapExchange exchange) {
        //FIXME:
        exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
    }

}
