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
package se.sics.ace.coap.dtlsProfile;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.dtlsProfile.DtlspPskStore;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AsInfo;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * Server for testing the DTLSProfileDeliverer class. 
 * 
 * The Junit tests are in TestDtlspClient, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDtlspServer {


    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {
            
            // set resource identifier
            super("helloWorld");
            
            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("Hello World!");
        }
    }
    
    /**
     * Definition of the Temp Resource
     */
    public static class TempResource extends CoapResource {
        
        /**
         * Constructor
         */
        public TempResource() {
            
            // set resource identifier
            super("temp");
            
            // set display name
            getAttributes().setTitle("Temp Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("19.0 C");
        }
    }
    
    private static TokenRepository tr = null;
    
    private static AuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;
    
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
      //Set up DTLSProfileTokenRepository
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_helloWorld", myResource);
        
        Set<String> actions2 = new HashSet<>();
        actions2.add("GET");
        Map<String, Set<String>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        createTR(valid);
        tr = TokenRepository.getInstance();
        
        byte[] key128a 
            = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      
        OneKey asymmetric = OneKey.generateKey(AlgorithmID.ECDSA_256);
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());

        
      //Set up the inner Authz-Info library
      ai = new AuthzInfo(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                null,
                valid, ctx);
      
      //Add a test token to authz-info
      byte[] key128
          = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      Map<Short, CBORObject> params = new HashMap<>(); 
      params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
      params.put(Constants.AUD, CBORObject.FromObject("rs1"));
      params.put(Constants.CTI, CBORObject.FromObject(
              "token1".getBytes(Constants.charset)));
      params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

      OneKey key = new OneKey();
      key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
      String kidStr = "someKey";
      CBORObject kid = CBORObject.FromObject(
              kidStr.getBytes(Constants.charset));
      key.add(KeyKeys.KeyId, kid);
      key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

      CBORObject cnf = CBORObject.NewMap();
      cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
      params.put(Constants.CNF, cnf);
      CWT token = new CWT(params);
      ai.processMessage(new LocalMessage(0, null, null, token.encode(ctx)));

      AsInfo asi 
      = new AsInfo("coaps://blah/authz-info/");
      Resource hello = new HelloWorldResource();
      Resource temp = new TempResource();
      Resource authzInfo = new CoapAuthzInfo(ai);

      rs = new CoapServer();
      rs.add(hello);
      rs.add(temp);
      rs.add(authzInfo);

      dpd = new CoapDeliverer(rs.getRoot(), tr, null, asi); 

      DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(
              new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
        config.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DtlspPskStore psk = new DtlspPskStore(ai);
        config.setPskStore(psk);
        config.setIdentity(asymmetric.AsPrivateKey(), asymmetric.AsPublicKey());
        config.setClientAuthenticationRequired(true);
        DTLSConnector connector = new DTLSConnector(config.build());
        rs.addEndpoint(
                new CoapEndpoint(connector, NetworkConfig.getStandard()));
        //Add a CoAP (no 's') endpoint for authz-info
        rs.addEndpoint(new CoapEndpoint(new InetSocketAddress(
                CoAP.DEFAULT_COAP_PORT)));
        
        rs.setMessageDeliverer(dpd);
        rs.start();
        System.out.println("Server starting");
    }
    
    /**
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(KissValidator valid) throws IOException {
        try {
            TokenRepository.create(valid, TestConfig.testFilePath 
                    + "tokens.json", null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws IOException, AceException {
        rs.stop();
        dpd.close();
        ai.close();
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }


}
