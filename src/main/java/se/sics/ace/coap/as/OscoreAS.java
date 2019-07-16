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

import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;

import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.PDP;
import se.sics.ace.as.Token;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;

/**
 * An Authorization Server that offers secure connections and authentication via OSCORE.
 * 
 * This server uses the following conventions:
 * 
 * alg = AES_CCM_16_64_128
 * salt = null
 * kdf = HKDF_HMAC_SHA_256
 * recipient_replay_window_size = 32
 * id_context = null
 * sender_id = asId
 * recipient_id = rs/client id
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoreAS extends CoapServer implements AutoCloseable {

    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAS.class.getName());
    
    /**
     * The token endpoint
     */
    Token t = null;
    
    /**
     * The introspect endpoint
     */
    Introspect i = null;

    private OscoreAceEndpoint token;

    private OscoreAceEndpoint introspect;
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @param port  the port number to run the server on
     * 
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db, 
            PDP pdp, TimeProvider time, 
            OneKey asymmetricKey, int port) 
                    throws AceException, OSException {
        this(asId, db, pdp, time, asymmetricKey, "token", "introspect", port,
                null, false);
    }
    
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
            OneKey asymmetricKey) throws AceException, OSException {
        this(asId, db, pdp, time, asymmetricKey, "token", "introspect",
                CoAP.DEFAULT_COAP_PORT, null, false);
    }
    
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @param tokenName the name of the token endpoint 
     *      (will be converted into the address as well)
     * @param introspectName  the name of the introspect endpoint 
     *      (will be converted into the address as well), if this is null,
     *      no introspection endpoint will be offered
     * @param port  the port number to run the server on
     * @param claims  the claim types to include in tokens issued by this 
     *                AS, can be null to use default set
     * @param setAudHeader  insert the AUD as header in the CWT.  
     * 
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db,
            PDP pdp, TimeProvider time, OneKey asymmetricKey, String tokenName,
            String introspectName, int port, Set<Short> claims, 
            boolean setAudHeader) throws AceException, OSException {
        this.t = new Token(asId, pdp, db, time, asymmetricKey, claims, setAudHeader);
        this.token = new OscoreAceEndpoint(tokenName, this.t);
        add(this.token);
        
        if (introspectName != null) {
            if (asymmetricKey == null) {
                this.i = new Introspect(pdp, db, time, null);
            } else {
                this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey());
            }
            this.introspect = new OscoreAceEndpoint(introspectName, this.i);
            add(this.introspect);    
        }
        this.addEndpoint(new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(CoAP.DEFAULT_COAP_PORT)
                .setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance())
                .build());  
        loadOscoreCtx(db, asId);        

    }

    /**
     * Load the OSCORE contexts from the database
     * 
     * @param db  the database connector
     * @param asId  the AS identifier
     * 
     * @throws AceException
     * @throws OSException
     */
    private static void loadOscoreCtx(CoapDBConnector db, String asId) throws AceException, OSException {
        Set<String> ids = db.getRSS();
        ids.addAll(db.getClients());
        
        for (String id : ids) {
            byte[] key = db.getKey(new PskPublicInformation(id));
            OSCoreCtx ctx = new OSCoreCtx(key, false, null, asId.getBytes(Constants.charset), 
                    id.getBytes(Constants.charset), null, null, null, null);
            OscoreCtxDbSingleton.getInstance().addContext(ctx);
        }
        LOGGER.finest("Loaded OSCORE contexts");
    }

    @Override
    public void close() throws Exception {
        LOGGER.info("Closing down OscoreAS ...");
        this.token.close();
        this.introspect.close();       
    }

}
