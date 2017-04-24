/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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

import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.PDP;
import se.sics.ace.as.Token;

/**
 * An authorization server listening to CoAP requests
 * over DTLS.
 * 
 * Create an instance of this server with the constructor then call
 * CoapsAS.start();
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapsAS extends CoapServer implements AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapsAS.class.getName());

    /**
     * The token endpoint
     */
    Token t = null;
    
    /**
     * The introspect endpoint
     */
    Introspect i = null;

    private CoapAceEndpoint token;

    private CoapAceEndpoint introspect;

    
    /**
     * Constructor.
     * 
     * @param asId 
     * @param db 
     * @param pdp 
     * @param time 
     * @param asymmetricKey 
     * @throws AceException 
     * @throws CoseException 
     * 
     */
    public CoapsAS(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
            OneKey asymmetricKey) throws AceException, CoseException {
        if (asymmetricKey == null) {
            this.i = new Introspect(pdp, db, time, null);
        } else {
            this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey());
        }
        this.t = new Token(asId, pdp, db, time, asymmetricKey); 
    
        this.token = new CoapAceEndpoint(this.t);
        this.introspect = new CoapAceEndpoint(this.i);

        add(this.token);
        add(this.introspect);

       DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(
               new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
       if (asymmetricKey != null && 
               asymmetricKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2 ) {
           LOGGER.info("Starting CoapsAS with PSK and RPK");
           config.setSupportedCipherSuites(new CipherSuite[]{
                   CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
       } else {
           LOGGER.info("Starting CoapsAS with PSK only");
           config.setSupportedCipherSuites(new CipherSuite[]{
                   CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
       }
       config.setPskStore(db);
       if (asymmetricKey != null) {
           config.setIdentity(asymmetricKey.AsPrivateKey(), 
                   asymmetricKey.AsPublicKey());
       }
      
       DTLSConnector connector = new DTLSConnector(config.build());
       addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
    }

    @Override
    public void close() throws Exception {
       LOGGER.info("Closing down CoapsAS ...");
       this.token.close();
       this.introspect.close();
    }
}
