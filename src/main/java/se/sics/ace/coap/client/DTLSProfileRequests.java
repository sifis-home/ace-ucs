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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedMultiPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapNotificationHandler;

/**
 * Implements getting a token from the /token endpoint for a client 
 * using the DTLS profile.
 * 
 * Also implements POSTing the token to the /authz-info endpoint at the 
 * RS.
 * 
 * Clients are expected to create an instance of this class when the want to
 * perform token requests from a specific AS.
 * 
 * @author Ludwig Seitz and Marco Tiloca and Marco Rasori
 *
 */
public class DTLSProfileRequests {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DTLSProfileRequests.class.getName() ); 

    /**
     * Sends a POST request to the /token endpoint of the AS to request an
     * access token. If the DTLS connection uses pre-shared symmetric keys 
     * we will use the key identifier (COSE kid) as psk_identity.
     * 
     * @param serverAddress  the server address including the port
     * @param tokenPath the path to the /token endpoint
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param key  the key to be used to secure the connection to the AS. 
     *  This MUST have a kid.
     * 
     * @return  the response 
     *
     * @throws AceException 
     */
    public static CoapResponse getToken(
            InetSocketAddress serverAddress, String tokenPath, CBORObject payload, OneKey key)
            throws AceException {

        if (tokenPath == null) {
            tokenPath = "token";
        }

        CoapClient client = buildClient(serverAddress, tokenPath, key);

        return getToken(client, payload);
    }


    public static CoapResponse getToken(CoapClient client, CBORObject payload)
            throws AceException {

        try {
            return client.post(payload.EncodeToBytes(), Constants.APPLICATION_ACE_CBOR);
        } catch (ConnectorException | IOException e) {
            LOGGER.severe("DTLSConnector error: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
    }


    public static CoapClient buildClient(
            InetSocketAddress serverAddress, String path, OneKey key)
            throws AceException {

        CBORObject type = key.get(KeyKeys.KeyType);
        if (type.equals(KeyKeys.KeyType_Octet)) {
            return buildPskClient(serverAddress, path, key);
        }
        else if (type.equals(KeyKeys.KeyType_EC2) || type.equals(KeyKeys.KeyType_OKP)) {
            return buildRpkClient(serverAddress, path, key);
        }
        else {
            LOGGER.severe("Unknown key type used for getting a token");
            throw new AceException("Unknown key type");
        }
    }


    public static CoapClient buildPskClient(
            InetSocketAddress serverAddress, String path, OneKey key)
            throws AceException {

        CBORObject type = key.get(KeyKeys.KeyType);
        if (!type.equals(KeyKeys.KeyType_Octet)) {
            LOGGER.severe("Unknown key type used for getting a token");
            throw new AceException("Unknown key type");
        }

        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
        dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES,
                Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));

        DtlsConnectorConfig.Builder builder =
                new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                    new InetSocketAddress(0));

        AdvancedMultiPskStore store = new AdvancedMultiPskStore();
        byte[] identityBytes = key.get(KeyKeys.KeyId).GetByteString();
        String identityStr = Base64.getEncoder().encodeToString(identityBytes);
        PskPublicInformation pskInfo = new PskPublicInformation(identityStr, identityBytes);
        store.addKnownPeer(serverAddress, pskInfo, key.get(KeyKeys.Octet_K).GetByteString());
        builder.setAdvancedPskStore(store);

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        return configureClient(dtlsConnector, serverAddress, path);
    }


    public static CoapClient buildRpkClient(
            InetSocketAddress serverAddress, String path, OneKey key)
            throws AceException {

        CBORObject type = key.get(KeyKeys.KeyType);
        if (!type.equals(KeyKeys.KeyType_EC2) && !type.equals(KeyKeys.KeyType_OKP)) {
            LOGGER.severe("Unknown key type used for getting a token");
            throw new AceException("Unknown key type");
        }

        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
        dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES,
                Collections.singletonList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));

        DtlsConnectorConfig.Builder builder
                = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                new InetSocketAddress(0));

        try {
            builder.setCertificateIdentityProvider(
                    new SingleCertificateProvider(key.AsPrivateKey(), key.AsPublicKey()));
        } catch (CoseException e) {
            LOGGER.severe("Failed to transform key: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                new X509Certificate[0], new RawPublicKeyIdentity[0], certTypes);
        builder.setAdvancedCertificateVerifier(verifier);

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        return configureClient(dtlsConnector, serverAddress, path);
    }


    private static CoapClient configureClient(
            DTLSConnector dtlsConnector, InetSocketAddress serverAddress, String path)
        throws AceException {
        CoapEndpoint ep = new CoapEndpoint.Builder()
                .setConnector(dtlsConnector)
                .setConfiguration(Configuration.getStandard())
                .build();

        CoapClient client = new CoapClient(
                "coaps", serverAddress.getHostString(),
                serverAddress.getPort(), path);
        client.setEndpoint(ep);
        try {
            dtlsConnector.start();
        } catch (IOException e) {
            LOGGER.severe("Failed to start DTLSConnector: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
        return client;
    }


    /**
     * Sends a GET request to the /trl endpoint of the AS to observe.
     * If the DTLS connection uses pre-shared symmetric keys
     * we will use the key identifier (COSE kid) as psk_identity.
     *
     * @param key  the key to be used to secure the connection to the AS.
     *  This MUST have a kid.
     *
     * @return  the relation
     *
     * @throws AceException
     */
    public static CoapObserveRelation makeObserveRequest(
            InetSocketAddress serverAddress, String trlPath, OneKey key, CoapHandler handler)
            throws AceException {

        if (trlPath == null) {
            trlPath = "trl";
        }
        CoapClient client = buildClient(serverAddress, trlPath, key);

        return makeObserveRequest(client, handler);
    }


    public static CoapObserveRelation makeObserveRequest(CoapClient client, CoapHandler handler) {

        Request request = buildTrlGetRequest(true);
        return client.observe(request, handler);
    }


    public static CoapResponse makePollRequest(
            InetSocketAddress serverAddress, String trlPath, OneKey key)
            throws AceException {

        if (trlPath == null) {
            trlPath = "trl";
        }
        CoapClient client = buildClient(serverAddress, trlPath, key);

        return makePollRequest(client);
    }


    public static CoapResponse makePollRequest(CoapClient client)
            throws AceException {

        Request request = buildTrlGetRequest(false);
        try {
            return client.advanced(request);
        } catch (ConnectorException | IOException e) {
            LOGGER.severe("Connector error: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
    }


    public static Request buildTrlGetRequest(boolean observe) {

        byte[] token = Bytes.createBytes(new Random(), 8);
        Request request = new Request(CoAP.Code.GET);
        request.setConfirmable(true);
        request.setToken(token);
        if (observe) {
            request.setObserve();
        }
        return request;
    }


    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token.
     * 
     * @param rsAddr  the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the token received from the getToken() method
     * @param key  an asymmetric key-pair to use with DTLS in a raw-public 
     *  key handshake
     * 
     * @return  the response 
     *
     * @throws AceException 
     */
    public static CoapResponse postToken(String rsAddr, CBORObject payload, OneKey key) throws AceException {
        return postToken(rsAddr, payload, Constants.APPLICATION_ACE_CBOR, key);
    }


    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token.
     *
     * @param rsAddr  the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param contentFormat  the CoAP content format to use for this message
     * @param payload  the token received from the getToken() method
     * @param key  an asymmetric key-pair to use with DTLS in a raw-public
     *  key handshake
     *
     * @return  the response
     *
     * @throws AceException
     */
    public static CoapResponse postToken(String rsAddr, CBORObject payload, int contentFormat, OneKey key) throws AceException {
        if (payload == null) {
            throw new AceException(
                    "Payload cannot be null when POSTing to authz-info");
        }
        Connector c = null;
        if (key != null) {
        	Configuration dtlsConfig = Configuration.getStandard();
        	dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
        	dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Collections.singletonList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        	dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
            DtlsConnectorConfig.Builder builder 
                = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                        new InetSocketAddress(0));

            try {
                builder.setCertificateIdentityProvider(
                        new SingleCertificateProvider(key.AsPrivateKey(), key.AsPublicKey()));
            } catch (CoseException e) {
                LOGGER.severe("Key is invalid: " + e.getMessage());
               throw new AceException("Aborting, key invalid: " 
                       + e.getMessage());
            }

            ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
            certTypes.add(CertificateType.RAW_PUBLIC_KEY);
            AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                    new X509Certificate[0], new RawPublicKeyIdentity[0], certTypes);
            builder.setAdvancedCertificateVerifier(verifier);

            c = new DTLSConnector(builder.build());
        } else {
            c = new UDPConnector(new InetSocketAddress(0), Configuration.getStandard());
        }
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setConfiguration(Configuration.getStandard()).build();
        CoapClient client = new CoapClient(rsAddr);
        client.setEndpoint(e);   
        try {
            e.start();
        } catch (IOException ex) {
            LOGGER.severe("Failed to start DTLSConnector: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }
               LOGGER.finest("Sending request payload: " + payload);
        CoapResponse r = null;
        try {
            r = client.post(payload.EncodeToBytes(), contentFormat);
        } catch (ConnectorException | IOException ex) {
            LOGGER.severe("DTLSConnector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }
        e.stop();
        return r;
    }
    
    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token for updating access rights.
     * 
     * @param rsAddr  the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the token received from the getToken() method
     * @param c  the CoAP client posting the access token
     * 
     * @return  the response 
     *
     * @throws AceException 
     */
    public static CoapResponse postTokenUpdate(String rsAddr, CBORObject payload, CoapClient c) throws AceException {
        return postTokenUpdate(rsAddr, payload, Constants.APPLICATION_CWT, c);
    }

    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token for updating access rights.
     *
     * @param rsAddr  the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the token received from the getToken() method
     * @param contentFormat  the CoAP content format to use for this message
     * @param c  the CoAP client posting the access token
     *
     * @return  the response
     *
     * @throws AceException
     */
    public static CoapResponse postTokenUpdate(String rsAddr, CBORObject payload, int contentFormat, CoapClient c) throws AceException {
        if (payload == null) {
            throw new AceException(
                    "Payload cannot be null when POSTing to authz-info");
        }

        //Submit the new token
        c.setURI(rsAddr);
        CoapResponse tokenPostResp = null;
        try {
        	tokenPostResp = c.post(payload.EncodeToBytes(), contentFormat);
        } catch (ConnectorException | IOException ex) {
            LOGGER.severe("DTLSConnector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }
        
        return tokenPostResp;
    }
        
    /**
     * Generates a Coap client for sending requests to an RS that will pass the
     *  access token through psk-identity in the DTLS handshake.
     * @param serverAddress  the address of the server and resource this client
     *  should talk to
     * @param token  the access token this client should use towards the server
     * @param key  the pre-shared key for use with this server.
     * 
     * @return  a CoAP client configured to pass the access token through the
     *  psk-identity in the handshake 
     */
    public static CoapClient getPskClient(InetSocketAddress serverAddress,
            CBORObject token, OneKey key) {
        if (serverAddress == null || serverAddress.getHostString() == null) {
            throw new IllegalArgumentException(
                    "Client requires a non-null server address");
        }
        if (token == null) {
            throw new IllegalArgumentException(
                    "PSK client requires a non-null access token");
        }
        if (key == null || key.get(KeyKeys.Octet_K) == null) {
            throw new IllegalArgumentException(
                    "PSK  client requires a non-null symmetric key");
        }
        
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
        dtlsConfig.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, null);
        dtlsConfig.set(DtlsConfig.DTLS_CURVES, null);
    	
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                    new InetSocketAddress(0));
        
        AdvancedMultiPskStore store = new AdvancedMultiPskStore();
        
        LOGGER.finest("Adding key for: " + serverAddress.toString());
        
        byte[] identityBytes = token.EncodeToBytes();
        String identityStr = Base64.getEncoder().encodeToString(identityBytes);
        PskPublicInformation pskInfo = new PskPublicInformation(identityStr, identityBytes);
        store.addKnownPeer(serverAddress, pskInfo, key.get(KeyKeys.Octet_K).GetByteString());
                
        builder.setAdvancedPskStore(store);
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setConfiguration(Configuration.getStandard()).build();
        CoapClient client = new CoapClient(serverAddress.getHostString());
        client.setEndpoint(e);   

        return client;    
    }
    
    
    /**
     * Generates a Coap client for sending requests to an RS that will use
     * a symmetric PoP key to connect to the server.
     * 
     * @param serverAddress  the address of the server and resource this client
     *  should talk to
     * @param kid  the kid that the client should use as PSK in the handshake
     * @param key  the pre-shared key for use with this server.
     * 
     * @return  a CoAP client configured to pass the access token through the
     *  psk-identity in the
     *  handshake 
     */
    public static CoapClient getPskClient(InetSocketAddress serverAddress,
            byte[] kid, OneKey key) {
        if (serverAddress == null || serverAddress.getHostString() == null) {
            throw new IllegalArgumentException(
                    "Client requires a non-null server address");
        }
        if (kid == null) {
            throw new IllegalArgumentException(
                    "PSK client requires a non-null kid");
        }
        if (key == null || key.get(KeyKeys.Octet_K) == null) {
            throw new IllegalArgumentException(
                    "PSK  client requires a non-null symmetric key");
        }
        
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
        dtlsConfig.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, null);
        dtlsConfig.set(DtlsConfig.DTLS_CURVES, null);
        
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                new InetSocketAddress(0));
        
        AdvancedMultiPskStore store = new AdvancedMultiPskStore();

        LOGGER.finest("Adding key for: " + serverAddress.toString());
        
        byte[] identityBytes = Util.buildDtlsPskIdentity(kid);
        String identityStr = Base64.getEncoder().encodeToString(identityBytes);
        PskPublicInformation pskInfo = new PskPublicInformation(identityStr, identityBytes);
        store.addKnownPeer(serverAddress, pskInfo, key.get(KeyKeys.Octet_K).GetByteString());
        
        builder.setAdvancedPskStore(store);
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder().
                setConfiguration(Configuration.getStandard()).setConnector(c).build();
        CoapClient client = new CoapClient(serverAddress.getHostString());
        client.setEndpoint(e);   

        return client;    
    }
    
    /**
     * Generates a Coap client for sending requests to an RS that will use
     * a raw public key to connect to the server.
     * 
     * @param clientKey  the raw asymmetric key of the client
     * @param rsPublicKey  the raw public key of the RS
     * @return   the CoAP client
     * @throws CoseException 
     */
    public static CoapClient getRpkClient(OneKey clientKey, OneKey rsPublicKey) 
            throws CoseException {
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Collections.singletonList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
    	
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                    new InetSocketAddress(0));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(clientKey.AsPrivateKey(), clientKey.AsPublicKey()));
        if (rsPublicKey != null) {

            RawPublicKeyIdentity[] identities = new RawPublicKeyIdentity[1];
            identities[0] = new RawPublicKeyIdentity(rsPublicKey.AsPublicKey());
            AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                    new X509Certificate[0], identities, null);

            builder.setAdvancedCertificateVerifier(verifier);
        }
        
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setConfiguration(Configuration.getStandard()).build();
        CoapClient client = new CoapClient();
        client.setEndpoint(e);   
        
        return client;    
    }    
}
