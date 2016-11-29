/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
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
package se.sics.ace.as;

import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

import COSE.CoseException;
import se.sics.ace.AceException;
import se.sics.ace.CoapRequest;
import se.sics.ace.Message;

/**
 * This class implements the token endpoint / resource (OAuth lingo vs CoAP lingo).
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapToken extends CoapResource implements AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(CoapToken.class.getName() );
    
    /**
     * The token library
     */
    private Token t;
    
    
    /**
     * Constructor.
     * 
     * @param name
     * @param t 
     */
    public CoapToken(String name, Token t) {
        super(name);
        this.t = t;        
    }
    
    /**
     * Handles the POST request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handlePOST(CoapExchange exchange) {
        CoapRequest req = null;
        try {
            req = CoapRequest.getInstance(exchange.advanced().getRequest());
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
            exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        }
        LOGGER.log(Level.FINEST, "Received request: " 
                + ((req==null)?"null" : req.toString()));
        Message m = this.t.processMessage(req);
        
        if (m instanceof CoapResponse) {
            CoapResponse res = (CoapResponse)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res.toString());
            //XXX: The profile should set the content format
            exchange.respond(res.getCode(), res.getPayload(), 
                    MediaTypeRegistry.APPLICATION_CBOR);
        }
        LOGGER.log(Level.SEVERE, "Token library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
    }

    @Override
    public void close() throws Exception {
        this.t.close();        
    }

}
 