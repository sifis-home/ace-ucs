package se.sics.ace.coap;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

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

    @Override
    public void sendRequest(Request request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void sendResponse(Response response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void sendEmptyMessage(EmptyMessage message) {
        // TODO Auto-generated method stub

    }

    @Override
    public void receiveRequest(Request request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void receiveResponse(Response response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void receiveEmptyMessage(EmptyMessage message) {
        // TODO Auto-generated method stub

    }

}
