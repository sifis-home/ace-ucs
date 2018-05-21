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
package se.sics.ace.interop;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.BasicConfigurator;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.CoapEndpointBuilder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

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
public class PlugtestRS {

    
    private static byte[] key128 = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static String asX 
        = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY 
        = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
   
    private static String rsX 
        = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY 
        = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    private static String rsD 
        = "00EA086573C683477D74EB7A0C63A6D031D5DEB10F3CC2876FDA6D3400CAA4E507";
              
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
     * Definition of the Lock Resource
     */
    public static class LockResource extends CoapResource {
        
        private boolean locked = true;
        
        /**
         * Constructor
         */
        public LockResource() {
            
            // set resource identifier
            super("lock");
            
            // set display name
            getAttributes().setTitle("Lock Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond(ResponseCode.CONTENT, this.locked 
                    ? CBORObject.True.EncodeToBytes() :
                            CBORObject.False.EncodeToBytes());
        }
        
        @Override
        public void handlePUT(CoapExchange exchange) {
            if (exchange.getRequestPayload() != null) {
                CBORObject newState = CBORObject.FromObject(
                        exchange.getRequestPayload());
                if (newState.getType().equals(CBORType.Boolean)) {
                    this.locked = newState.AsBoolean();
                    exchange.respond(ResponseCode.CHANGED);
                }
            }
            exchange.respond(ResponseCode.BAD_REQUEST);
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
        BasicConfigurator.configure();
        
      //Set up DTLSProfileTokenRepository
        Set<Short> r = new HashSet<>();
        r.add(Constants.GET);
        
        Set<Short> rw = new HashSet<>();
        rw.add(Constants.GET);
        rw.add(Constants.PUT);
        
        Map<String, Set<Short>> helloWorldResource = new HashMap<>();
        helloWorldResource.put("helloWorld", r);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("helloWorld", helloWorldResource);
        
        Map<String, Set<Short>> rLockResource = new HashMap<>();
        rLockResource.put("lock", r);
        myScopes.put("r_Lock", rLockResource);
 
        Map<String, Set<Short>> rwLockResource = new HashMap<>();
        rwLockResource.put("lock", rw);
        myScopes.put("rw_Lock", rwLockResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        
        createTR(valid);
        tr = TokenRepository.getInstance();
      
        CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject x = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsX));
        CBORObject y = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsY));
        CBORObject d = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
        OneKey rpk = new OneKey(rpkData); 
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        
      //Set up the inner Authz-Info library
      ai = new AuthzInfo(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                null,
                valid, ctx);
      
      //Add a test token to authz-info
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
      CBORObject payload = CBORObject.FromObject(
              token.encode(ctx).EncodeToBytes());
      ai.processMessage(new LocalMessage(0, null, null, payload));

      AsInfo asi 
      = new AsInfo("coaps://blah/token");
      Resource hello = new HelloWorldResource();
      Resource lock = new LockResource();
      Resource authzInfo = new CoapAuthzInfo(ai);

      rs = new CoapServer();
      rs.add(hello);
      rs.add(lock);
      rs.add(authzInfo);

      dpd = new CoapDeliverer(rs.getRoot(), tr, null, asi); 

      
      DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder()
              .setAddress(
                      new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
        config.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DtlspPskStore psk = new DtlspPskStore(ai);
        config.setPskStore(psk);
        config.setIdentity(rpk.AsPrivateKey(), rpk.AsPublicKey());
        config.setClientAuthenticationRequired(true);
        DTLSConnector connector = new DTLSConnector(config.build());
        CoapEndpoint cep = new CoapEndpointBuilder().setConnector(connector)
                .setNetworkConfig(NetworkConfig.getStandard()).build();
        rs.addEndpoint(cep);
        //Add a CoAP (no 's') endpoint for authz-info
        CoapEndpoint aiep = new CoapEndpointBuilder().setInetSocketAddress(
                new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
        rs.addEndpoint(aiep);
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
            TokenRepository.create(valid, "tokens.json", null);
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
        new File("tokens.json").delete();
    }


}
