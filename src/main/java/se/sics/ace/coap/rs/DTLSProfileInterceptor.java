package se.sics.ace.coap.rs;

import java.util.List;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

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
 * @author Ludwig Seitz
 *
 */
public class DTLSProfileInterceptor implements MessageInterceptor {
    
    /**
     * The token repository
     */
    private TokenRepository tr;
    
    /**
     * The instrospection handler
     */
    private IntrospectionHandler i;
    
    /**
     * Constructor. 
     * @param tr  the token repository.
     * @param i  the introspection handler or null if there isn't any.
     */
    public DTLSProfileInterceptor(TokenRepository tr, IntrospectionHandler i) {
        this.tr = tr;
    }
    

    @Override
    public void sendRequest(Request request) {
        // Nothing to do

    }

    @Override
    public void sendResponse(Response response) {
        // Nothing to do

    }

    @Override
    public void sendEmptyMessage(EmptyMessage message) {
        // Nothing to do

    }

    @Override
    public void receiveRequest(Request request) {
        String subject = request.getSenderIdentity().getName();
        String resource = request.getOptions().getUriPathString();
        String action = request.getCode().toString();    
//        
//        if (!this.tr.canAccess(kid, subject, resource, action, 
//                new KissTime(), this.i)) {
//            request.cancel();
//            //FIXME: Send answer
//        }
    }

    @Override
    public void receiveResponse(Response response) {
        // Nothing to do

    }

    @Override
    public void receiveEmptyMessage(EmptyMessage message) {
        // Nothing to do

    }

}
