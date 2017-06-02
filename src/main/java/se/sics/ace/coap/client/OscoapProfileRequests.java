package se.sics.ace.coap.client;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.OSCoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.stack.oscoap.OscoapCtx;
import org.eclipse.californium.core.network.stack.oscoap.OscoapCtxDB;

import com.upokecenter.cbor.CBORObject;

import COSE.OneKey;
import se.sics.ace.AceException;

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
     * @param rsAddr
     * @param payload
     * @param db
     * @return
     */
    public static CoapResponse postToken(String rsAddr, CBORObject payload, 
            OscoapCtxDB db) {
        return sendMessage(rsAddr, payload, db);
    }
    
    /**
     * 
     * @param addr
     * @param payload
     * @param db
     * @return
     */
    private static CoapResponse sendMessage(String addr, CBORObject payload, 
            OscoapCtxDB db) {
        OSCoapClient client = getClient(db);
        client.setURI(addr);
        return client.post(payload.EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
    }
    
    /**
     * @param db
     * @return
     */
    public static OSCoapClient getClient(OscoapCtxDB db) {
        return new OSCoapClient(db);
    }


}
