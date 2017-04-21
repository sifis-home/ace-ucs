package se.sics.ace.coap.rs;

import java.util.List;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;

/**
 * This interceptor should process incoming and outgoing messages at the RS 
 * according to the specifications of the ACE framework 
 * (draft-ietf-ace-oauth-authz) and the DTLS profile of that framework
 * (draft-gerdes-ace-dtls-authorize).
 * 
 * It's specific task is to match requests against existing access tokens
 * to see if the request is authorized.
 * 
 * @author Ludwig Seitz
 *
 */
public class DTLSProfileDeliverer extends ServerMessageDeliverer {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DTLSProfileDeliverer.class.getName());
    
    /**
     * The token repository
     */
    private DTLSProfileTokenRepository tr;
    
    /**
     * The instrospection handler
     */
    private IntrospectionHandler i;
    
    /**
     * Constructor. 
     * @param root  the root of the resources that this deliverer controls
     * @param tr  the token repository.
     * @param i  the introspection handler or null if there isn't any.
     */
    public DTLSProfileDeliverer(Resource root, DTLSProfileTokenRepository tr, 
            IntrospectionHandler i) {
        super(root);
        this.tr = tr;
    }
    
    @Override
    public void deliverRequest(final Exchange ex) {
        Request request = ex.getCurrentRequest();
        String subject = request.getSenderIdentity().getName();
        String kid = this.tr.getKid(subject);
               
        String resource = request.getOptions().getUriPathString();
        String action = request.getCode().toString();  
      
        try {
            int res = this.tr.canAccess(kid, subject, resource, action, 
                    new KissTime(), this.i);
           //     ex.sendResponse(new Response(ResponseCode.FORBIDDEN));
            //    ex.sendResponse(new Response(ResponseCode.METHOD_NOT_ALLOWED));
                //FIXME: Send a response
                //DOUBLE FIXME: Find out how to distinguish 4.03 and 4.05 duh!
        } catch (AceException e) {
            //FIXME: request.cancel();
            LOGGER.severe("Error in DTLSProfileInterceptor.receiveRequest(): "
                    + e.getMessage());
            
        }
        super.deliverRequest(ex);
    }

}
