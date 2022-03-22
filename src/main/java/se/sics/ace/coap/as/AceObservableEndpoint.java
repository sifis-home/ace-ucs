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
package se.sics.ace.coap.as;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.oscore.OSCoreResource;
import se.sics.ace.*;
import se.sics.ace.as.*;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class implements the ACE endpoint/resource
 * (OAuth lingo vs CoAP lingo) trl.
 * 
 * @author Marco Rasori
 *
 */
public class AceObservableEndpoint extends CoapResource implements AutoCloseable {

    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(AceObservableEndpoint.class.getName());

    /**
     * The trl library
     */
//    private Endpoint e;       <== changed to Trl since we need to call the setQueryParameters method
    private Trl e;

    /**
     * Constructor.
     *
     * @param name  the resource name (should be  "trl")
     * @param e  the endpoint library instance
     */
    public AceObservableEndpoint(String name, Trl e) {
        super(name, true);
        this.e = e;
        this.setObservable(true);
        this.setObserveType(CoAP.Type.CON);
        this.getAttributes().setObservable();
    }

    /**
     * Default constructor.
     *
     * @param e  the endpoint library instance
     */
    public AceObservableEndpoint(Trl e) {
        super("trl", true);
        this.e = e;
        this.setObservable(true);
        this.setObserveType(CoAP.Type.NON);
        this.getAttributes().setObservable();
    }


    @Override
    public void handleGET(CoapExchange exchange) {

        CoapReq req = null;
        try {
            req = CoapReq.getInstance(exchange.advanced().getRequest());
        } catch (AceException e) {//Message didn't have CBOR payload
            LOGGER.info(e.getMessage());
            exchange.respond(ResponseCode.BAD_REQUEST);
        }
        LOGGER.log(Level.FINEST, "Received request: "
                + ((req == null) ? "null" : req.toString()));

        //Map<String, Integer> queryParams = parseQueryParameters(exchange);
        this.e.setQueryParameters(parseQueryParameters(exchange));
        this.e.setHasObserve(req.getOptions().hasObserve());

        Message m = this.e.processMessage(req);
        if (m instanceof CoapRes) {
            CoapRes res = (CoapRes)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res);

            // FIXME: Are we supposed to use ACE_TRL_CBOR even if we return
            //        an INTERNAL_SERVER_ERROR?
            //        Currently, the draft does not implement this error.
            exchange.respond(ResponseCode.CONTENT, res.getRawPayload(),
                    Constants.APPLICATION_ACE_TRL_CBOR);
            return;
        }
        if (m == null) {//Wasn't a CoAP message
            return;
        }
        LOGGER.severe(this.e.getClass().getName()
                + " library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);

    }

    /**
     * Extract the query parameters from the exchange and create a map
     *
     * @param exchange the exchange containing the query parameters
     *
     * @return the map containing the query parameter names and values
     */
    Map<String, Integer> parseQueryParameters (CoapExchange exchange) {

        Map<String, Integer> queryParameters = new HashMap<>();

        String nStr = exchange.getQueryParameter("diff");
        if (nStr != null) {
            queryParameters.put("diff", Integer.parseInt(nStr));
        }

        String pmaxStr = exchange.getQueryParameter("pmax");
        if (pmaxStr != null) {
            queryParameters.put("pmax", Integer.parseInt(pmaxStr));
        }

        String cursorStr = exchange.getQueryParameter("cursor");
        if (cursorStr != null) {
            queryParameters.put("cursor", Integer.parseInt(cursorStr));
        }

        return queryParameters;
    }

    @Override
    public void close() throws Exception {
        this.e.close();
    }

}


