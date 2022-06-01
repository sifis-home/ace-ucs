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

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.*;

/**
 * An authorization server listening to CoAP requests
 * over DTLS.
 * 
 * Create an instance of this server with the constructor then call
 * CoapsAS.start();
 * 
 * @author Ludwig Seitz and Marco Tiloca and Marco Rasori
 *
 */
public class DtlsAS extends CoapServer implements AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DtlsAS.class.getName());

    /**
     * The token endpoint
     */
    Token t = null;
    
    /**
     * The introspect endpoint
     */
    Introspect i = null;

    /**
     * The trl endpoint
     */
    Trl r = null;

    private CoapDtlsEndpoint token;

    private CoapDtlsEndpoint introspect;

    private AceObservableEndpoint trl;

    private RevocationHandler rh;

    private Timer timer;

    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS for RPK handshakes,
     *   can be null if the AS only ever does PSK handshakes
     * @param port  the port number to run the server on
     * 
     * @throws AceException 
     * @throws CoseException 
     * 
     */
    public DtlsAS(String asId, CoapDBConnector db,
                  PDP pdp, TimeProvider time,
                  OneKey asymmetricKey, int port)
                    throws AceException, CoseException {
        this(asId, db, pdp, time, asymmetricKey,
                "token", "introspect", new TrlConfig(), port,
                null, false);
    }
    
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS for RPK handshakes,
     *   can be null if the AS only ever does PSK handshakes
     * @throws AceException 
     * @throws CoseException 
     * 
     */
    public DtlsAS(String asId, CoapDBConnector db,
                  PDP pdp, TimeProvider time,
                  OneKey asymmetricKey)
                    throws AceException, CoseException {
        this(asId, db, pdp, time, asymmetricKey,
                "token", "introspect", new TrlConfig(),
                CoAP.DEFAULT_COAP_SECURE_PORT, null, false);
    }
    
    /**
     * Constructor with endpoint names
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS for RPK handshakes,
     *      can be null if the AS only ever does PSK handshakes
     * @param tokenName  the name of the token endpoint 
     *      (will be converted into the address as well)
     * @param introspectName  the name of the introspect endpoint 
     *      (will be converted into the address as well), if this is null,
     *      no introspection endpoint will be offered
     * @param trlConfig contains the properties of the trl, such as its name,
     *                  the maximum size of the trl portion for each peer, etc.
     *                  if null, no observable endpoint for notification of TRL
     *                  changes will be offered
     * @param port  the port number to run the server on
     * @param claims  the claim types to include in tokens issued by this 
     *                AS, can be null to use default set.
     * @param setAudHeader  insert the AUD as header in the CWT. 
     * See {@link se.sics.ace.as.Token} for details.
     * @throws AceException 
     * @throws CoseException 
     * 
     */
    public DtlsAS(String asId,
                  CoapDBConnector db,
                  PDP pdp,
                  TimeProvider time,
                  OneKey asymmetricKey,
                  String tokenName,
                  String introspectName,
                  TrlConfig trlConfig,
                  int port,
                  Set<Short> claims,
                  boolean setAudHeader)
                    throws AceException, CoseException {

        this.t = new Token(asId, pdp, db,
                time, asymmetricKey, claims, setAudHeader, null);
        this.token = new CoapDtlsEndpoint(tokenName, this.t);
        add(this.token);
        
        if (introspectName != null) {
            if (asymmetricKey == null) {
                this.i = new Introspect(pdp, db, time, null, null);
            } else {
                this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey(), null);
            }
            this.introspect = new CoapDtlsEndpoint(introspectName, this.i);
            add(this.introspect);    
        }

        if (trlConfig != null) {
            this.r = new Trl(db, null, trlConfig.getnMax(), trlConfig.getMaxBatchSize());  // double check
            this.trl = new AceObservableEndpoint(trlConfig.getName(), this.r);
            add(this.trl);
            if (trlConfig.isUseRevocationHandler()) {
                this.rh = new RevocationHandler(db, pdp, time, null, this.r.getDiffSetsMap(), trl);
                pdp.setRevocationHandler(this.rh);
//            // to remove, it triggers a revocation. Only for test purposes
//            // while implementing the revoke method on the pdp
//            timer = new Timer();
//            timer.schedule(new DtlsAS.UpdateTask(rh), 15000);
            }
            else LOGGER.warning("Starting Trl without RevocationHandler");
            // The endpoint will be observable,
            // but notifications will never be sent to peers
            // since no revocations will occur
        }

        pdp.setTokenEndpoint(t);

        Configuration dtlsConfig = Configuration.getStandard();
       dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
       dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);



       if (asymmetricKey != null && 
               asymmetricKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2 ) {
           LOGGER.info("Starting CoapsAS with PSK and RPK");
           dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
       } else {
           LOGGER.info("Starting CoapsAS with PSK only");
           dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
       }
        
       DtlsConnectorConfig.Builder config =  new DtlsConnectorConfig.Builder(dtlsConfig)
               .setAddress(new InetSocketAddress(port));

       ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
       certTypes.add(CertificateType.RAW_PUBLIC_KEY);
       certTypes.add(CertificateType.X_509);
       AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(new X509Certificate[0],
               new RawPublicKeyIdentity[0], certTypes);
       config.setAdvancedCertificateVerifier(verifier);

       config.setAdvancedPskStore(db);
       if (asymmetricKey != null) {
           config.setCertificateIdentityProvider(
                   new SingleCertificateProvider(asymmetricKey.AsPrivateKey(), asymmetricKey.AsPublicKey()));
       }
       DTLSConnector connector = new DTLSConnector(config.build());
       
       addEndpoint(new CoapEndpoint.Builder()
               .setConnector(connector).setConfiguration(
                       Configuration.getStandard()).build());
       //Add a CoAP (no 's') endpoint for error messages
       //CoapEndpoint coap = new CoapEndpointBuilder().setInetSocketAddress(
       //       new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
       //addEndpoint(coap);
    }

//    /**
//     * Scheduled task to revoke a given token. (Temporary and for test purposes)
//     */
//    public class UpdateTask extends TimerTask {
//
//        RevocationHandler rh;
//
//        public UpdateTask(RevocationHandler rh) {
//            this.rh = rh;
//        }
//
//        @Override
//        public void run() {
//            try{
//                System.out.println("START REVOKE METHOD");
//                rh.revoke("AAAAAAAAAAA=");  // put here the token cti you want to revoke
//            } catch (AceException e) {
//                LOGGER.info(e.getMessage());
//                System.out.println("FAILED REVOKE METHOD");
//            }
//        }
//    }

    @Override
    public void close() throws Exception {
       LOGGER.info("Closing down DtlsAS ...");
       this.token.close();
       this.introspect.close();
    }
}
