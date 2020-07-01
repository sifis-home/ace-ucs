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
package se.sics.ace.coap.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.coap.rs.oscoreProfile.OscoreSecurityContext;


/**
 * Implements getting a token from the /token endpoint for a client 
 * using the OSCORE profile.
 * 
 * Also implements POSTing the token to the /authz-info endpoint at the 
 * RS.
 * 
 * Clients are expected to create an instance of this class when the want to
 * perform token requests from a specific AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class OSCOREProfileRequestsGroupOSCORE {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OSCOREProfileRequests.class.getName() ); 

    /**
     * Sends a POST request to the /token endpoint of the AS to request an
     * access token.
     * 
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param ctx  the OSCORE context shared with the AS
     * 
     * @return  the response 
     *
     * @throws AceException 
     * @throws OSException 
     */
    public static Response getToken(String asAddr, CBORObject payload, 
            OSCoreCtx ctx) throws AceException, OSException {

        Request r = new Request(Code.POST);
        r.getOptions().setOscore(new byte[0]);
        r.setPayload(payload.EncodeToBytes());
        OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
        db.addContext(asAddr, ctx);
        
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setCoapStackFactory(new OSCoreCoapStackFactory());
        builder.setCustomCoapStackArgument(db);
        Endpoint clientEndpoint = builder.build();
        CoapClient client = new CoapClient(asAddr);
        client.setEndpoint(clientEndpoint);  
        try {
            return client.advanced(r).advanced();
        } catch (ConnectorException | IOException e) {
            LOGGER.severe("Connector error: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token.
     * 
     * @param rsAddr  the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param asResp  the response from the AS containing the token
     *      and the access information
     * @param askForSignInfo  FIXME
     * @param askForPubKeyEnc  FIXME
     * 
     * @return  the response 
     *
     * @throws AceException 
     * @throws OSException 
     */
    public static Response postToken(String rsAddr, Response asResp, boolean askForSignInfo, boolean askForPubKeyEnc) 
            throws AceException, OSException {
        if (asResp == null) {
            throw new AceException(
                    "asResp cannot be null when POSTing to authz-info");
        }
        
        CBORObject asPayload;
        try {
            asPayload = CBORObject.DecodeFromBytes(asResp.getPayload());
        } catch (CBORException e) {
            throw new AceException("Error parsing CBOR payload: " 
                    + e.getMessage());
        }
               
        if (!asPayload.getType().equals(CBORType.Map)) {
            throw new AceException("AS response was not a CBOR map");
        }
        
        CBORObject token = asPayload.get(
                CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            throw new AceException("AS response did not contain a token");
        }
        
        CBORObject cnf = asPayload.get(
                CBORObject.FromObject(Constants.CNF));
        if (cnf == null) {
            throw new AceException("AS response did not contain a cnf");
        }
      
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token);
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
        	payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);
        
        CoapClient client = new CoapClient(rsAddr);

        LOGGER.finest("Sending request payload: " + payload);
        
        Response r = null;
        try {
            r = client.post(
                    payload.EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR).advanced();
        } catch (ConnectorException | IOException ex) {
            LOGGER.severe("Connector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }

        if (r == null) {
            throw new AceException("RS did not respond");
        }
        CBORObject rsPayload;
        try {
            rsPayload = CBORObject.DecodeFromBytes(r.getPayload());
        } catch (CBORException e) {
            throw new AceException("Error parsing CBOR payload: " 
                    + e.getMessage());
        }
        
        if (!rsPayload.getType().equals(CBORType.Map)) {
            throw new AceException("RS didn't respond with a CBOR map");
        }
        
        CBORObject n2C = rsPayload.get(
                CBORObject.FromObject(Constants.NONCE2));
        if (n2C == null || !n2C.getType().equals(CBORType.ByteString)) {
            throw new AceException(
                    "Missing or malformed 'nonce2' in RS response");
        }
        
        CBORObject rsNoncePoP = rsPayload.get(
                CBORObject.FromObject(Constants.KDCCHALLENGE));
        if (rsNoncePoP == null || !rsNoncePoP.getType().equals(CBORType.ByteString)) {
            throw new AceException(
                    "Missing or malformed PoP rsnonce in RS response");
        }
        
        if (askForSignInfo || askForPubKeyEnc) {
        	
        	if (!rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)) ||
        		 rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType() != CBORType.Array) {
                	throw new AceException(
                			"Missing or malformed sign_info in the RS response, although requested");
        	}

        }
        
        byte[] n2 = n2C.GetByteString();
        byte[] contextId = new byte[n1.length+n2.length];
        System.arraycopy(n1, 0, contextId, 0, n1.length);
        System.arraycopy(n2, 0, contextId, n1.length, n2.length);
        
        
        OscoreSecurityContext osc = new OscoreSecurityContext(cnf);
        
        OSCoreCtx ctx = osc.getContext(true, n1, n2);
        OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
        db.addContext(ctx);
        db.addContext(rsAddr, ctx);
        
        return r;
        
    }
    
    
    /**
     * Generates a Coap client for sending requests to an RS using OSCORE.
     * Note that the OSCORE context for the RS should already be configured 
     * in the OSCoreCtxDb at this point.
     * 
     * @param serverAddress  the address of the server and resource this client
     *  should talk to.
     * 
     * @return  a CoAP client configured to pass the access token through the
     *  psk-identity in the handshake 
     * @throws AceException 
     * @throws OSException 
     * @throws URISyntaxException 
     */
    public static CoapClient getClient(InetSocketAddress serverAddress) 
            throws AceException, OSException {
        if (serverAddress == null || serverAddress.getHostString() == null) {
            throw new IllegalArgumentException(
                    "Client requires a non-null server address");
        }
        OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
        if (db.getContext(serverAddress.getHostName()) == null) {
            throw new AceException("OSCORE context not set for address: " 
                    + serverAddress);
        }
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setCoapStackFactory(new OSCoreCoapStackFactory());
        builder.setCustomCoapStackArgument(db);
        Endpoint clientEndpoint = builder.build();
        CoapClient client = new CoapClient(serverAddress.getHostString());
        client.setEndpoint(clientEndpoint);
        return client;    
    }
}
