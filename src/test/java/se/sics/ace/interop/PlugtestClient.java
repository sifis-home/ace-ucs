/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.CoapEndpointBuilder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * @author Ludwig Seitz
 *
 */
public class PlugtestClient {
   
    private static byte[] client1 =
        {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static byte[] client2 =
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static byte[] client4 =
        {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    //Needed to show token content
    private static byte[] rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    //Needed to show token content
    private static byte[] rs2 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    //Needed to show token content
    private static CwtCryptoCtx ctx1 = null;
    
    //Needed to show token content
    private static CwtCryptoCtx ctx2 = null;
    
    private static String cX 
        = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY 
        = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    private static String cD
        = "00A43BAA7ED22FF2699BA62CA4999359B146F065A95C4E46017CD25EB89A94AD29";
    
    private static String asX 
        = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY 
        = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
    
    private static String rsX 
        = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY 
        = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    
    private static byte[] kid = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBC};
    
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(PlugtestClient.class.getName() ); 
    
    /**
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args)
            throws Exception {
        
        if (args.length < 2) { 
            System.out.println("First argument should be the number of the"
                    + " test case, second the address of the other endpoint"
                    + "(AS/RS) without the path");
            // args[0] is the test case, 
            //args[1] is the address of the other endpoint
            return;
        }
        
        //Setup RPKs
        CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject x = CBORObject.FromObject(PlugtestAS.hexString2byteArray(cX));
        CBORObject y = CBORObject.FromObject(PlugtestAS.hexString2byteArray(cY));
        CBORObject d = CBORObject.FromObject(PlugtestAS.hexString2byteArray(cD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
        OneKey rpk = new OneKey(rpkData);  
        
        CBORObject asRpkData = CBORObject.NewMap();
        asRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        asRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        asRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject as_x = CBORObject.FromObject(PlugtestAS.hexString2byteArray(asX));
        CBORObject as_y = CBORObject.FromObject(PlugtestAS.hexString2byteArray(asY));
        asRpkData.Add(KeyKeys.EC2_X.AsCBOR(), as_x);
        asRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), as_y);
        OneKey asRPK = new OneKey(asRpkData);  
        
        CBORObject rsRpkData = CBORObject.NewMap();
        rsRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rsRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rsRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject rs_x = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsX));
        CBORObject rs_y = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsY));
        rsRpkData.Add(KeyKeys.EC2_X.AsCBOR(), rs_x);
        rsRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), rs_y);
        OneKey rsRPK = new OneKey(rsRpkData);
        
        
        //Setup PSKs
        CBORObject pskData = CBORObject.NewMap();
        pskData.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client1));
        String kidStr = "key128";
        byte[] kid = Base64.decode(kidStr);
        pskData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        OneKey client1PSK = new OneKey(pskData);
        
        CBORObject pskData2 = CBORObject.NewMap();
        pskData2.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData2.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client2));
        String kidStr2 = "key128";
        byte[] kid2 = Base64.decode(kidStr2);
        pskData2.Add(KeyKeys.KeyId.AsCBOR(), kid2);
        OneKey client2PSK = new OneKey(pskData2);
       
        CBORObject pskData4 = CBORObject.NewMap();
        pskData4.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData4.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client4));
        String kidStr4 = "key128";
        byte[] kid4 = Base64.decode(kidStr4);
        pskData4.Add(KeyKeys.KeyId.AsCBOR(), kid4);
        OneKey client4PSK = new OneKey(pskData4);
               
        int testcase = Integer.parseInt(args[0]);
        String uri = args[1]; 
        // add schema if not present
        if (!uri.contains("://")) {
            uri = "coaps://" + uri;
        }
        if (uri.endsWith("/")) {
            uri = uri.substring(-1);
        }

        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx1 = CwtCryptoCtx.encrypt0(rs1, coseP.getAlg().AsCBOR());
        
        ctx2 = CwtCryptoCtx.encrypt0(rs2, coseP.getAlg().AsCBOR());
        
        
        switch (testcase) {

        case 1 :  //AS /token tests
            uri = uri + "/token";
            System.out.println("=====Starting Test 1.1======");
            DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setClientOnly();
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
            builder.setClientAuthenticationRequired(false);        
            DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
            CoapEndpointBuilder ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            CoapEndpoint e = ceb.build();
            CoapClient client = new CoapClient(uri);
            client.setEndpoint(e);   
            e.start();
            CBORObject payload = CBORObject.FromObject("blah");
            LOGGER.finest("Sending request");
            try {
                client.post(payload.EncodeToBytes(), 
                        MediaTypeRegistry.APPLICATION_CBOR);
            } catch (RuntimeException r) {
                System.out.println(r.getMessage());
                e.stop();
                System.out.println("=====End Test 1.1======");
            }
          
            System.out.println("=====Starting Test 1.2======");
            builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});      
            builder.setPskStore(new StaticPskStore("client1", client1));
            dtlsConnector = new DTLSConnector(builder.build());
            ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            e = ceb.build();
            client = new CoapClient(uri);
            client.setEndpoint(e);
            e.start();  
            Map<Short, CBORObject> params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            LOGGER.finest("Sending request");
            CoapResponse res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            e.stop();
            System.out.println("=====End Test 1.2======"); 
            
            System.out.println("=====Starting Test 1.3======");
            builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setPskStore(new StaticPskStore("client2", client2));
            dtlsConnector = new DTLSConnector(builder.build());
            ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            e = ceb.build();
            client = new CoapClient(uri);
            client.setEndpoint(e);
            e.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            //params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.3======"); 

            System.out.println("=====Starting Test 1.4======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, 
                    CBORObject.FromObject(Constants.GT_PASSWORD));
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.4======"); 

            System.out.println("=====Starting Test 1.5======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("test"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.5======");

            System.out.println("=====Starting Test 1.6======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.6======"); 

            System.out.println("=====Starting Test 1.7======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            CBORObject cnf = CBORObject.NewMap();
            cnf.Add(Constants.COSE_KEY, client2PSK.AsCBOR());
            params.put(Constants.CNF, cnf);
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            e.stop();
            System.out.println("=====End Test 1.7======"); 
            
            System.out.println("=====Starting Test 1.8======");
            builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setIdentity(rpk.AsPrivateKey(), 
                    rpk.AsPublicKey());
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
            builder.setClientAuthenticationRequired(true);        
            dtlsConnector = new DTLSConnector(builder.build());
            ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            e = ceb.build();
            client = new CoapClient(uri);
            client.setEndpoint(e);
            e.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            //params.put(Constants.SCOPE, 
            //        CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.8======");
            
            System.out.println("=====Starting Test 1.9======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            cnf = CBORObject.NewMap();
            cnf.Add(Constants.COSE_KEY, rpk.PublicKey().AsCBOR());
            params.put(Constants.CNF, cnf);
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.9======");
            
            System.out.println("=====Starting Test 1.10======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("RS2"));
            cnf = CBORObject.NewMap();
            cnf.Add(Constants.COSE_KEY, rpk.PublicKey().AsCBOR());
            params.put(Constants.CNF, cnf);
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            e.stop();
            System.out.println("=====End Test 1.10======");
            
            System.out.println("=====Starting Test 1.11======");
            builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setPskStore(new StaticPskStore("client4", client4));
            dtlsConnector = new DTLSConnector(builder.build());
            ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            e = ceb.build();
            client = new CoapClient(uri);
            client.setEndpoint(e);
            e.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("rw_Lock"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res);
            System.out.println("=====End Test 1.11======");
            
            System.out.println("=====Starting Test 1.12======");
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("r_Lock rw_Lock"));
            params.put(Constants.AUD, CBORObject.FromObject("RS1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            printResults(res); 
            e.stop();
            System.out.println("=====End Test 1.12======");
            break; 
            
        case 2: //Tests against RS1
            System.out.println("=====Starting Test 2.1======");
            Connector c = new UDPConnector();
            e = new CoapEndpoint.CoapEndpointBuilder().setConnector(c)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();
            uri = uri.replace("coaps:", "coap:");
            uri = uri + "/ace/helloWorld"; 
            client = new CoapClient(uri);
            client.setEndpoint(e);   
            try {
                c.start();
            } catch (IOException ex) {
                LOGGER.severe("Failed to start Connector: " 
                        + ex.getMessage());
                throw new AceException(ex.getMessage());
            }
            LOGGER.finest("Sending request");
            res = client.get();
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            System.out.println(CBORObject.DecodeFromBytes(res.getPayload()));
            c.stop();
            System.out.println("=====End Test 2.1======");
            
            System.out.println("=====Starting Test 2.2======");
            uri = uri.replace("ace/helloWorld", "authz-info");
            res = DTLSProfileRequests.postToken(
                    uri, CBORObject.FromObject("test"), null);
            printResults(res);
            System.out.println("=====End Test 2.2======");
            
            System.out.println("=====Starting Test 2.3======");
            //Make the token
            Map<Short, CBORObject> claims = new HashMap<>();
            claims.put(Constants.SCOPE, CBORObject.FromObject("HelloWorld"));
            claims.put(Constants.AUD, CBORObject.FromObject("RS2"));
            claims.put(Constants.ISS, CBORObject.FromObject("AS"));
            OneKey key = new OneKey();
            key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
            CBORObject kidCB = CBORObject.FromObject(kid);
            key.add(KeyKeys.KeyId, kidCB);
            //Using client1 here just for testing, could be random
            key.add(KeyKeys.Octet_K, CBORObject.FromObject(client1));
            CBORObject cbor = CBORObject.NewMap();
            cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
            claims.put(Constants.CNF, cbor);
            CWT token = new CWT(claims);
            CBORObject tokenCB = token.encode(ctx2);
            payload = CBORObject.FromObject(tokenCB.EncodeToBytes());
            res = DTLSProfileRequests.postToken(uri, payload, null);
            printResults(res);
            System.out.println("=====End Test 2.3======");
            
            System.out.println("=====Starting Test 2.4======");
            //Encrypt token with correct key this time
            tokenCB = token.encode(ctx1);
            payload = CBORObject.FromObject(tokenCB.EncodeToBytes());
            res = DTLSProfileRequests.postToken(uri, payload, null);
            printResults(res);
            System.out.println("=====End Test 2.4======");
            
            System.out.println("=====Starting Test 2.5======");
            //Make the token
            claims = new HashMap<>();
            claims.put(Constants.SCOPE, CBORObject.FromObject("test"));
            claims.put(Constants.AUD, CBORObject.FromObject("RS1"));
            claims.put(Constants.ISS, CBORObject.FromObject("AS"));
            claims.put(Constants.CNF, cbor);
            token = new CWT(claims);
            tokenCB = token.encode(ctx1);
            payload = CBORObject.FromObject(tokenCB.EncodeToBytes());
            res = DTLSProfileRequests.postToken(uri, payload, null);
            printResults(res);
            System.out.println("=====End Test 2.5======");
            
            System.out.println("=====Starting Test 2.6======");
            
            System.out.println("=====End Test 2.6======");
            
            System.out.println("=====Starting Test 2.7======");
            
            System.out.println("=====End Test 2.7======");
            
            System.out.println("=====Starting Test 2.8======");
            
            System.out.println("=====End Test 2.8======");
            
            System.out.println("=====Starting Test 2.9======");
            
            System.out.println("=====End Test 2.9======");
            break;
            
        case 3: //Tests against RS2
            System.out.println("=====Starting Test 2.10======");
            
            System.out.println("=====End Test 2.10======");
            
            System.out.println("=====Starting Test 2.11======");
            
            System.out.println("=====End Test 2.11======");
            
            System.out.println("=====Starting Test 2.12======");
            
            System.out.println("=====End Test 2.12======");
            
            System.out.println("=====Starting Test 2.13======");
            
            System.out.println("=====End Test 2.13======");
            
            System.out.println("=====Starting Test 2.14======");
            
            System.out.println("=====End Test 2.14======");
            
            System.out.println("=====Starting Test 2.15======");
            
            System.out.println("=====End Test 2.15======");
            break;
        default : //Error
            throw new RuntimeException("Unkown test series, use 1,2 or 3");
        }     
    }

    
    private static void printResults(CoapResponse res) throws CoseException, Exception {
        if (res != null) {
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
                Map<String, CBORObject> params = Constants.unabbreviate(
                        CBORObject.DecodeFromBytes(res.getPayload()));
                System.out.println(params);
                //Print token is there is one
                if (params.containsKey("access_token")) {
                    CBORObject token = params.get("access_token");
                    CBORObject tokenAsCbor = CBORObject.DecodeFromBytes(token.GetByteString());
                    if (!tokenAsCbor.getType().equals(CBORType.Array)) {
                        return;
                    }
                    CWT cwt = null;
                    try {
                        cwt = CWT.processCOSE(tokenAsCbor.EncodeToBytes(), ctx1);
                    } catch (InvalidCipherTextException e) {
                        cwt = CWT.processCOSE(tokenAsCbor.EncodeToBytes(), ctx2);
                    }
                    //Check if we can introspect this token
                    Map<Short, CBORObject> claims = cwt.getClaims();
                    CBORObject map = Constants.getCBOR(claims);
                    System.out.println("Token: ");
                    System.out.println(Constants.unabbreviate(map));
                }
            }
        } else {
            System.out.print("No response received");
        }
    }
}
