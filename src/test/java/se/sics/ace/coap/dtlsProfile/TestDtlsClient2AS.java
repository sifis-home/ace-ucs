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
package se.sics.ace.coap.dtlsProfile;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.as.Token;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start an AS in another thread
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlsClient2AS {
    
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    static RunTestServer srv = null;
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            DtlsASTestServer.stop();
        }
        
        @Override
        public void run() {
            try {
                DtlsASTestServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    DtlsASTestServer.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    
    /**
     * This sets up everything for the tests including the server
     */
    @BeforeClass
    public static void setUp() {
        srv = new RunTestServer();
        srv.run();
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    
    // @Ignore
    /**
     * Test connecting with RPK without authenticating the client.
     * The Server should reject that.
     * 
     * @throws Exception 
     */
    /*
    @Test
    public void testNoClientAuthN() throws Exception {
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setRpkTrustAll();
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint.Builder ceb = new CoapEndpoint.Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();

        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, at.encode());
        try {
            client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        } catch (IOException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Server should not accept DTLS connection");       
    }
    */

    /**
     * Test CoapToken using PSK
     * 
     * @throws Exception 
     */
    @Test
    public void testCoapToken() throws Exception {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setPskStore(new StaticPskStore("clientA", key128));
        //builder.setIdentity(asymmetricKey.AsPrivateKey(), 
        //       asymmetricKey.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint.Builder ceb = new CoapEndpoint.Builder();
        ceb.setConnector(dtlsConnector);
        
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(ceb.build());

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
    }
    
    
    /**
     * Test CoapToken using PSK. After having received the first token, the client
     * sends a second request for a new access token to update access rights
     * 
     * @throws Exception 
     */
    @Test
    public void testCoapTokenUpdateAccessRights() throws Exception {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setPskStore(new StaticPskStore("clientA", key128));
        //builder.setIdentity(asymmetricKey.AsPrivateKey(), 
        //       asymmetricKey.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint.Builder ceb = new CoapEndpoint.Builder();
        ceb.setConnector(dtlsConnector);
        
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(ceb.build());

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);    
        
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.get(Constants.CNF).ContainsKey(Constants.COSE_KEY));
        Assert.assertEquals(3, map.get(Constants.CNF).get(Constants.COSE_KEY).size());
        Assert.assertEquals(true, map.get(Constants.CNF).get(Constants.COSE_KEY).ContainsKey(KeyKeys.KeyId.AsCBOR()));
        Assert.assertEquals(true, map.get(Constants.CNF).get(Constants.COSE_KEY).ContainsKey(KeyKeys.KeyType.AsCBOR()));
        Assert.assertEquals(true, map.get(Constants.CNF).get(Constants.COSE_KEY).ContainsKey(KeyKeys.Octet_K.AsCBOR()));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
        
        // Store the 'kid' of the symmetric PoP key for later check
        byte[] kid = map.get(Constants.CNF).get(Constants.COSE_KEY).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
        
        
        // Ask for a new Token for updating access rights, with a different 'scope'
        
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_temp rw_config rw_light foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
        					   Constants.APPLICATION_ACE_CBOR); 
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        map = Constants.getParams(res);
        System.out.println(map);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.get(Constants.CNF).ContainsKey(Constants.COSE_KEY));
        Assert.assertEquals(2, map.get(Constants.CNF).get(Constants.COSE_KEY).size());
        Assert.assertEquals(true, map.get(Constants.CNF).get(Constants.COSE_KEY).ContainsKey(KeyKeys.KeyId.AsCBOR()));
        Assert.assertEquals(true, map.get(Constants.CNF).get(Constants.COSE_KEY).ContainsKey(KeyKeys.KeyType.AsCBOR()));
        Assert.assertArrayEquals(kid, map.get(Constants.CNF).get(Constants.COSE_KEY).get(KeyKeys.KeyId.AsCBOR()).GetByteString());
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config rw_light"));
        
    }
    
    
    /**
     * Test CoapIntrospect using RPK
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospect() throws Exception {
        OneKey key = new OneKey(
                CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        //builder.setPskStore(new StaticPskStore("rs1", key256));
        builder.setIdentity(key.AsPrivateKey(), 
                key.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setRpkTrustAll();
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        CoapEndpoint.Builder ceb = new CoapEndpoint.Builder();
        ceb.setConnector(dtlsConnector);
       
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(ceb.build());
               
        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, CBORObject.FromObject(at.encode().EncodeToBytes()));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("actuators"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("co2"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));
        
    }
}
