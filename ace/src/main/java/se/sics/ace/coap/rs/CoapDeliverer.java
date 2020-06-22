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
package se.sics.ace.coap.rs;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;

/**
 * This deliverer processes incoming and outgoing messages at the RS 
 * according to the specifications of the ACE framework 
 * (draft-ietf-ace-oauth-authz).
 * 
 *  It can handle tokens passed through the DTLS handshake as specified in
 *  draft-ietf-ace-dtls-authorize.
 * 
 * It's specific task is to match requests against existing access tokens
 * to see if the request is authorized.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDeliverer implements MessageDeliverer {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDeliverer.class.getName());
    
    /**
     * The introspection handler
     */
    private IntrospectionHandler i;
    
    /**
     * The class managing the AS Request Creation Hints
     */
    private AsRequestCreationHints asRCH;
  
    /** 
     * The ServerMessageDeliverer that processes the request
     * after access control has been done
     */
    private ServerMessageDeliverer d;
    

    /**
     * Constructor. 
     * 
     * Note: This expects that a TokenRepository has been created.
     * 
     * @param root  the root of the resources that this deliverer controls
     * @param i  the introspection handler or null if there isn't any.
     * @param asRCHM  the AS Request Creation Hints Manager.
     * @throws AceException   if the token repository is not initialized
     */
    public CoapDeliverer(Resource root,
            IntrospectionHandler i, AsRequestCreationHints asRCHM) 
                    throws AceException {
        if (TokenRepository.getInstance() == null) {
            throw new AceException("Must initialize TokenRepository");
        }
        this.d = new ServerMessageDeliverer(root);
        this.asRCH = asRCHM; 
    }
  
    //Really the TokenRepository _should not_ be closed here
    @SuppressWarnings("resource") 
    @Override
    public void deliverRequest(final Exchange ex) {
        Request request = ex.getCurrentRequest();
        Response r = null;
        //authz-info is not under access control
        try {
            URI uri = new URI(request.getURI());
            //Need to check with and without trailing / in case there are query options
            if (uri.getPath().endsWith("/authz-info") || uri.getPath().endsWith("/authz-info/") ) { 
                this.d.deliverRequest(ex);
                return;
            }
        } catch (URISyntaxException e) {
            LOGGER.warning("Request-uri " + request.getURI()
                    + " is invalid: " + e.getMessage());
            r = new Response(ResponseCode.BAD_REQUEST);
            ex.sendResponse(r);
            return;
        }      
       
       
        String subject = null;
        
        if (request.getSourceContext() == null 
                || request.getSourceContext().getPeerIdentity() == null) {
            //XXX: Kludge for OSCORE since cf-oscore doesn't set PeerIdentity
        	
        	// Old way for retrieving only the OSCORE Sender ID of the message originator
        	/*
            if (ex.getCryptographicContextID()!= null) {                
                subject = new String(ex.getCryptographicContextID(),
                        Constants.charset);    
            }*/
            
        	Request req = ex.getRequest();
            try {
				subject = CoapReq.getInstance(req).getSenderId();
				if (subject == null) {
				    LOGGER.warning("Unauthenticated client tried to get access");
				    failUnauthz(null, ex);
				    return;
				}
			} catch (AceException e) {
	            LOGGER.severe("Error while retrieving the client identity: " + e.getMessage());
			}
        } else  {
            subject = request.getSourceContext().getPeerIdentity().getName();
        }

        TokenRepository tr = TokenRepository.getInstance();
        if (tr == null) {
            LOGGER.finest("TokenRepository not initialized");
            ex.sendResponse(new Response(
                    ResponseCode.INTERNAL_SERVER_ERROR));
        }
        String kid = TokenRepository.getInstance().getKid(subject);
       
        if (kid == null) {//Check if this was the Base64 encoded kid map
            try {
                CBORObject cbor = CBORObject.DecodeFromBytes(
                        Base64.getDecoder().decode(subject));
                if (cbor.getType().equals(CBORType.Map)) {
                   CBORObject ckid = cbor.get(KeyKeys.KeyId.AsCBOR());
                   if (ckid != null && ckid.getType().equals(
                           CBORType.ByteString)) {
                      kid = new String(ckid.GetByteString(), 
                              Constants.charset);
                   } else { //No kid in that CBOR map or it isn't a bstr
                       failUnauthz(kid, ex);
                       return;
                   }
                } else {//Some weird CBOR that is not a map here
                   failUnauthz(kid, ex);
                   return;
                }                
            } catch (CBORException e) {//Really no kid found for that subject
                LOGGER.finest("Error while trying to parse some "
                        + "subject identity to CBOR: " + e.getMessage());
               failUnauthz(kid, ex);
               return;
            } catch (IllegalArgumentException e) {//Text was not Base64 encoded
                LOGGER.finest("Error: " + e.getMessage() 
                + " while trying to Base64 decode this: " + subject);
                failUnauthz(kid, ex);
                return;
            }
           
        }
               
        String resource = request.getOptions().getUriPathString();
        short action = (short) request.getCode().value;  
      
        try {
            int res = TokenRepository.getInstance().canAccess(
                    kid, subject, resource, action, this.i);
            switch (res) {
            case TokenRepository.OK :
                this.d.deliverRequest(ex);
                return;
            case TokenRepository.UNAUTHZ :
               failUnauthz(kid,ex);
               return;
            case TokenRepository.FORBID :
                r = new Response(ResponseCode.FORBIDDEN);
                try {
                    r.setPayload(this.asRCH.getHints(ex.getCurrentRequest(), 
                            kid).EncodeToBytes());
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    LOGGER.severe("cnonce creation failed: " + e.getMessage());
                    ex.sendResponse(r); //Send response without payload
                }
                ex.sendResponse(r);
                return;
            case TokenRepository.METHODNA :
                r = new Response(ResponseCode.METHOD_NOT_ALLOWED);
                try {
                    r.setPayload(this.asRCH.getHints(ex.getCurrentRequest(),
                            kid).EncodeToBytes());
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    LOGGER.severe("cnonce creation failed: " + e.getMessage());
                    ex.sendResponse(r);
                }
                ex.sendResponse(r);
                return;
            default :
                LOGGER.severe("Error during scope evaluation,"
                        + " unknown result: " + res);
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
               return;
            }
        } catch (AceException e) {
            LOGGER.severe("Error in CoapDeliverer.deliverRequest(): "
                    + e.getMessage());    
        } catch (IntrospectionException e) {
            LOGGER.info("Introspection error, "
                    + "message processing aborted: " + e.getMessage());
           if (e.getMessage().isEmpty()) {
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
           }
           CBORObject map = CBORObject.NewMap();
           map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
           map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
           r = new Response(ResponseCode.BAD_REQUEST);
           r.setPayload(map.EncodeToBytes());
           ex.sendResponse(r);
        }
    }
    
    /**
     * Fail a request with 4.01 Unauthorized.
     * 
     * @param kid  the kid of the key for the security association 
     *              or null if it was not established
     */
    private void failUnauthz(String kid, Exchange ex) {
        Response r = new Response(ResponseCode.UNAUTHORIZED);
        try {
            r.setPayload(this.asRCH.getHints(
                    ex.getCurrentRequest(), kid).EncodeToBytes());
            ex.sendResponse(r);
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | AceException e) {
            LOGGER.severe("cnonce creation failed: " + e.getMessage());
            ex.sendResponse(r); //Just send UNAUTHORIZED without a payload
        }
       
    }

    @Override
    public void deliverResponse(Exchange exchange, Response response) {
        this.d.deliverResponse(exchange, response);        
    }

}
