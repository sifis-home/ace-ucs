package se.sics.ace.coap.client;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.OSCoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.stack.oscoap.OscoapCtxDB;

import com.upokecenter.cbor.CBORObject;

/**
 * This class implements the OSCOAP profile of ACE for the client-side requests:
 *  1. Getting a token from the AS /token endpoint
 *  2. Sending a token to the RS /authz-info endpoint
 *  3. Sending a request to an RS resource
 *  
 * @author Ludwig Seitz
 *
 */
public class OscoapProfileRequests {

    /**
     * Sends a POST request to the /token endpoint of the AS to request an
     * access token. 
     * 
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param db  the OSCOAP context database
     * 
     * @return  the response 
     */
    public static CoapResponse getToken(String asAddr, CBORObject payload, 
            OscoapCtxDB db) {   
        return sendMessage(asAddr, payload, db);
    }
    
    
    /**
     * Sends a token to the /authz-info endpoint of the RS using POST.
     * 
     * @param rsAddr  the full address of the /authz-info endpoint
     * @param payload  the payload of the request, containing access token.
     * @param db  the OSCOAP context database
     * 
     * @return  the response
     */
    public static CoapResponse postToken(String rsAddr, CBORObject payload, 
            OscoapCtxDB db) {
        return sendMessage(rsAddr, payload, db);
    }
    
    /**
     * Send a POST message to an RS. Used internally by other methods.
     * 
     * @param addr  the address to use
     * @param payload  the payload to send
     * @param db  the OSCOAP context database
     * @return
     */
    private static CoapResponse sendMessage(String addr, CBORObject payload, 
            OscoapCtxDB db) {
        OSCoapClient client = getClient(addr, db);
        return client.post(payload.EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
    }
    
    /**
     * Get an OSCOAP client for sending messages to a RS.
     * 
     * @param uri  the address of the resource this client should contact
     * @param db  the OSCOAP context database
     *  
     * @return  the OSCoapClient instance
     */
    public static OSCoapClient getClient(String uri, OscoapCtxDB db) {
        return new OSCoapClient(uri, db);
    }


}
