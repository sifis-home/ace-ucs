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
import java.util.Base64;
import java.util.Collections;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.InMemoryRpkTrustStore;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;

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
 * @author Ludwig Seitz and Marco Tiloca
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
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param key  the key to be used to secure the connection to the AS. 
     *  This MUST have a kid.
     * 
     * @return  the response 
     *
     * @throws AceException 
     */
    public static CoapResponse getToken(String asAddr, CBORObject payload, 
            OneKey key) throws AceException {
        DtlsConnectorConfig.Builder builder
            = new DtlsConnectorConfig.Builder().setAddress(
                    new InetSocketAddress(0));

        builder.setClientAuthenticationRequired(true);
        builder.setSniEnabled(false);
        CBORObject type = key.get(KeyKeys.KeyType);
        if (type.equals(KeyKeys.KeyType_Octet)) {
            String keyId = new String(
                    key.get(KeyKeys.KeyId).GetByteString(),
                    Constants.charset);
            builder.setPskStore(new StaticPskStore(
                    keyId, key.get(KeyKeys.Octet_K).GetByteString()));
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        } else if (type.equals(KeyKeys.KeyType_EC2) || type.equals(KeyKeys.KeyType_OKP)){
            try {
                builder.setIdentity(key.AsPrivateKey(), key.AsPublicKey());
            } catch (CoseException e) {
                LOGGER.severe("Failed to transform key: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
            builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        } else {
            LOGGER.severe("Unknwon key type used for getting a token");
            throw new AceException("Unknown key type");
        }

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());      
        CoapEndpoint ep = new CoapEndpoint.Builder()
                .setConnector(dtlsConnector)
                .setNetworkConfig(NetworkConfig.getStandard())
                .build();
        CoapClient client = new CoapClient(asAddr);
        client.setEndpoint(ep);
        try {
            dtlsConnector.start();
        } catch (IOException e) {
            LOGGER.severe("Failed to start DTLSConnector: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
        try {
            return client.post(
                    payload.EncodeToBytes(), 
                    Constants.APPLICATION_ACE_CBOR);
        } catch (ConnectorException | IOException e) {
            LOGGER.severe("DTLSConnector error: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
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
    public static CoapResponse postToken(String rsAddr, CBORObject payload, 
            OneKey key) throws AceException {
        if (payload == null) {
            throw new AceException(
                    "Payload cannot be null when POSTing to authz-info");
        }
        Connector c = null;
        if (key != null) {
            DtlsConnectorConfig.Builder builder 
                = new DtlsConnectorConfig.Builder().setAddress(
                        new InetSocketAddress(0));

            builder.setClientAuthenticationRequired(true);
            builder.setSniEnabled(false);
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
            builder.setRpkTrustAll();
            try {
                builder.setIdentity(key.AsPrivateKey(), key.AsPublicKey());
            } catch (CoseException e) {
                LOGGER.severe("Key is invalid: " + e.getMessage());
               throw new AceException("Aborting, key invalid: " 
                       + e.getMessage());
            }
            c = new DTLSConnector(builder.build());
        } else {
            c = new UDPConnector();
        }
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setNetworkConfig(NetworkConfig.getStandard()).build();
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
            r = client.post(
                    payload.EncodeToBytes(), 
                    Constants.APPLICATION_ACE_CBOR);
        } catch (ConnectorException | IOException ex) {
            LOGGER.severe("DTLSConnector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }
        e.stop();
        return r;
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
        
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder().setAddress(
                    new InetSocketAddress(0));
        builder.setClientAuthenticationRequired(true);
        builder.setSniEnabled(false);
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        
        InMemoryPskStore store = new InMemoryPskStore();
       
        String identity = Base64.getEncoder().encodeToString(
                token.EncodeToBytes());
        LOGGER.finest("Adding key for: " + serverAddress.toString());
        store.addKnownPeer(serverAddress, identity, 
                key.get(KeyKeys.Octet_K).GetByteString());
        builder.setPskStore(store);
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setNetworkConfig(NetworkConfig.getStandard()).build();
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
        
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder().setAddress(
                new InetSocketAddress(0));
        builder.setClientAuthenticationRequired(true);
        builder.setSniEnabled(false);
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        
        InMemoryPskStore store = new InMemoryPskStore();

        // NEW WAY, where a structure with "cnf" is used as "psk_identity"
        CBORObject identityStructure = CBORObject.NewMap();
        CBORObject cnfStructure = CBORObject.NewMap();
        CBORObject COSEKeyStructure = CBORObject.NewMap();
        COSEKeyStructure.Add(CBORObject.FromObject(KeyKeys.KeyType), KeyKeys.KeyType_Octet);
        COSEKeyStructure.Add(CBORObject.FromObject(KeyKeys.KeyId), kid);
        cnfStructure.Add(Constants.COSE_KEY_CBOR, COSEKeyStructure);
        identityStructure.Add(CBORObject.FromObject(Constants.CNF), cnfStructure);
        String identity = Base64.getEncoder().encodeToString(identityStructure.EncodeToBytes());      
        
        // OLD WAY, with only the kid used as "psk_identity"
        // String identity = new String(kid, Constants.charset);
        
        LOGGER.finest("Adding key for: " + serverAddress.toString());
        store.addKnownPeer(serverAddress, identity, 
                key.get(KeyKeys.Octet_K).GetByteString());
        builder.setPskStore(store);
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder()
                .setConnector(c).setNetworkConfig(
                        NetworkConfig.getStandard()).build();
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
        DtlsConnectorConfig.Builder builder 
            = new DtlsConnectorConfig.Builder().setAddress(
                    new InetSocketAddress(0));
        builder.setClientAuthenticationRequired(true);
        builder.setSniEnabled(false);
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setIdentity(clientKey.AsPrivateKey(), clientKey.AsPublicKey());
        if (rsPublicKey != null) {
            InMemoryRpkTrustStore store = new InMemoryRpkTrustStore(
                    Collections.singleton(new RawPublicKeyIdentity(
                            rsPublicKey.AsPublicKey())));
            builder.setRpkTrustStore(store);
        }
        
        Connector c = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder().setConnector(c)
                .setNetworkConfig(NetworkConfig.getStandard()).build();
        CoapClient client = new CoapClient();
        client.setEndpoint(e);   
        
        return client;    
    }    
}
