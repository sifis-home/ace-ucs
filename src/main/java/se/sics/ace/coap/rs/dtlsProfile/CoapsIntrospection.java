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
package se.sics.ace.coap.rs.dtlsProfile;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.coap.BksStore;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;

/**
 * An introspection handler using CoAPS (i.e. CoAP over DTLS) to connect to an AS.
 *
 * @author Ludwig Seitz
 *
 */
public class CoapsIntrospection implements IntrospectionHandler {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapsIntrospection.class.getName());
    
        /**
     * The CoAP client
     */
    private CoapClient client = null;
    
    /**
     * Constructor, builds a client that uses raw public keys.
     * 
     * @param rpk  the raw public key 
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * 
     */
    public CoapsIntrospection(OneKey rpk, String introspectAddress) 
            throws CoseException, IOException {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(0));
        builder.setIdentity(rpk.AsPrivateKey(), 
                rpk.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
        dtlsConnector.start();
    }
    
    /**
     * Constructor, builds a client that uses pre-shared symmetric keys.
     * 
     * @param psk  the pre-shared key
     * @param pskIdentity  the identity associated to the pre-shared key
     * @param keystoreLocation 
     * @param keystorePwd 
     * @param addr2idFile 
     * @param addr2id 
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * 
     */
    public CoapsIntrospection(byte[] psk, String pskIdentity,
            String keystoreLocation, String keystorePwd, String addr2idFile,
            Map<InetSocketAddress, String> addr2id,
            String introspectAddress) throws CoseException, IOException,
            NoSuchAlgorithmException, CertificateException, KeyStoreException,
            NoSuchProviderException {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(
                new InetSocketAddress(0));
        BksStore.init(keystoreLocation, keystorePwd, addr2idFile);
        BksStore keystore = new BksStore(
                keystoreLocation, keystorePwd, addr2idFile);
        builder.setPskStore(keystore);
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint(dtlsConnector, 
                NetworkConfig.getStandard());
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
        dtlsConnector.start();
    }
    
    @Override
    public Map<Short, CBORObject> getParams(byte[] tokenReference) 
            throws AceException, IntrospectionException {
        LOGGER.info("Sending introspection request on " + tokenReference);
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN,  CBORObject.FromObject(tokenReference));
        params.put(Constants.TOKEN_TYPE_HINT, CBORObject.FromObject("pop")); 
        CoapResponse response =  this.client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
        if (!response.getCode().equals(ResponseCode.CREATED)) {
            //Some error happened
            if (response.getPayload() == null) {//This was a server error
                throw new IntrospectionException(response.getCode().value, "");
            }
            //Client error
            throw new IntrospectionException(response.getCode().value, 
                    CBORObject.DecodeFromBytes(
                            response.getPayload()).toString());
        }
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        return map;
        
    }

}
