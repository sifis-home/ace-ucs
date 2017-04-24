package se.sics.ace.coap.rs;

import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;

import se.sics.ace.AceException;
import se.sics.ace.examples.KissTime;
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
     * The introspection handler
     */
    private IntrospectionHandler i;
    
    /**
     * The AS information message sent back to unauthorized requesters
     */
    private DTLSProfileAsInfo asInfo;
    
    /**
     * Constructor. 
     * @param root  the root of the resources that this deliverer controls
     * @param tr  the token repository.
     * @param i  the introspection handler or null if there isn't any.
     * @param asInfo  the AS information to send for client authz errors.
     */
    public DTLSProfileDeliverer(Resource root, DTLSProfileTokenRepository tr, 
            IntrospectionHandler i, DTLSProfileAsInfo asInfo) {
        super(root);
        this.tr = tr;
        this.asInfo = asInfo;
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
            Response r = null;
            switch (res) {
            case TokenRepository.OK :
                super.deliverRequest(ex);
                break;
            case TokenRepository.UNAUTHZ :
                r = new Response(ResponseCode.UNAUTHORIZED);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                break;
            case TokenRepository.FORBID :
                r = new Response(ResponseCode.FORBIDDEN);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                break;
            case TokenRepository.METHODNA :
                r = new Response(ResponseCode.METHOD_NOT_ALLOWED);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                break;
            default :
                LOGGER.severe("Error during scope evaluation,"
                        + " unknown result: " + res);
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
            }
        } catch (AceException e) {
            LOGGER.severe("Error in DTLSProfileInterceptor.receiveRequest(): "
                    + e.getMessage());    
        }
    }
}
