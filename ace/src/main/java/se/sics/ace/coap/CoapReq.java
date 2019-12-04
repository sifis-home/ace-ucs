/*******************************************************************************
 * Copyright (c) 2019, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.coap;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.oscore.OSCoreCtx;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapReq implements Message {

    /**
     * The parameters in the payload of this message as a Map for convenience,
     * if the payload is a CBOR Map.
     */
    private Map<Short, CBORObject> parameters;
    
    /**
     * The underlying Request from Californium
     */
    private Request request;

    /**
     * The underlying CoapExchange from Californium
     * Used for retrieving the Sender ID when OSCORE is used
     */
    private CoapExchange exchange;
    
    /**
     * Create a request from an underlying Californium request.
     * Payload if any MUST be in CBOR.
     * 
     * @param req  the underlying Californium request
     * @param exchange  the underlying Californium CoapExchange
     * @throws AceException 
     */
    protected CoapReq(Request req, CoapExchange exchange) throws AceException {
        this.request = req;
        this.exchange = exchange;
        CBORObject cborPayload = null;
        if (req.getPayload() != null) {
            try {
                cborPayload = CBORObject.DecodeFromBytes(req.getPayload());
            } catch (CBORException ex) {
                throw new AceException(ex.getMessage());
            }
            if (cborPayload != null 
                    && cborPayload.getType().equals(CBORType.Map)) {
                this.parameters = Constants.getParams(cborPayload);
            }
        }
    }
    

    @Override
    public byte[] getRawPayload() {
        return this.request.getPayload();
    }

    @Override
    public String getSenderId() {
        EndpointContext ctx = this.request.getSourceContext();
        if (ctx==null) {
            return null;
        }
        //XXX: kludge since OSCORE doesn't set PeerIdentity
        if (ctx instanceof DtlsEndpointContext) {
            Principal p = ctx.getPeerIdentity();
            if (p==null) {
                return null;
            }
            return p.getName();
        } 
       
        OSCoreCtx osctx = OscoreCtxDbSingleton.getInstance()
                .getContextByToken(this.request.getToken());
        
        //If retrieving the OSCORE context using the method above failed,
        //instead take the Sender ID from the exchange and use that to get the context.
        //Then extract the other parties recipient ID and return that.
        if(osctx == null) {
        	byte[] requestSenderID = exchange.advanced().getCryptographicContextID();
        	osctx = OscoreCtxDbSingleton.getInstance()
                    .getContext(requestSenderID);
        	
        	if(osctx != null) {
	            String recipientId = "";
	            if (osctx.getIdContext() != null) {
	            	recipientId += Base64.encodeBytes(osctx.getIdContext());
	            }
	            recipientId += new String(osctx.getRecipientId(), Constants.charset);    
	            return recipientId;
        	}
        }
        
        //Code below is how it was before
        
        if (osctx == null) {
            return null;
        }
        
        String senderId = "";
        if (osctx.getIdContext() != null) {
            senderId += Base64.encodeBytes(osctx.getIdContext());
        }
        senderId += new String(osctx.getSenderId(), Constants.charset);    
        return senderId;
     
    }

    @Override
    public Set<Short> getParameterNames() {
        if (this.parameters != null) {
            return this.parameters.keySet();
        }
        return null;
    }

    @Override
    public CBORObject getParameter(Short name) {
        if (this.parameters != null) {
            return this.parameters.get(name);
        }
        return null;
    }

    @Override
    public Map<Short, CBORObject> getParameters() {
        if (this.parameters != null) {
            Map<Short, CBORObject> map = new HashMap<>();
            map.putAll(this.parameters);
            return map;
        }
        return null;
    }

    @Override
    public Message successReply(int code, CBORObject payload) {
        ResponseCode coapCode = ResponseCode.valueOf(code);
        CoapRes res = new CoapRes(coapCode, payload);       
        return res;
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        ResponseCode coapCode = ResponseCode.valueOf(failureReason);
        CoapRes res = new CoapRes(coapCode, payload);
        return res;
    }
    
    /**
     * Create a CoAPRequest from a Californium <code>Request</code>.
     * 
     * @param req  the Californium Request
     * @param exchange the Californium CoapExchange
     * @return  the ACE CoAP request
     * @throws AceException 
     */
    public static CoapReq getInstance(Request req, CoapExchange exchange) throws AceException {
        return new CoapReq(req, exchange);
    }

    @Override
    public int getMessageCode() {
        return this.request.getCode().value;
    }
    
    /**
     * @return  the CoAP token associated with this message
     */
    public Token getToken() {
        return this.request.getToken();
    }
}
