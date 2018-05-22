package se.sics.ace.interop;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

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

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;

/**
 * @author Ludwig Seitz
 *
 */
public class PlugtestClient {
   
    private static byte[] key128 =
        {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static String cX 
        = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY 
        = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    private static String cD
        = "00A43BAA7ED22FF2699BA62CA4999359B146F065A95C4E46017CD25EB89A94AD29";
    
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(PlugtestClient.class.getName() ); 
    
    /**
     * @param args
     * @throws CoseException
     * @throws IOException
     * @throws AceException
     */
    public static void main(String[] args)
            throws CoseException, IOException, AceException {
        
        if (args.length < 2) { 
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
        
        //Setup PSK
        CBORObject pskData = CBORObject.NewMap();
        pskData.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        String kidStr = "key128";
        byte[] kid = Base64.decode(kidStr);
        pskData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        OneKey psk = new OneKey(pskData);
       
        
        
        int testcase = Integer.parseInt(args[0]);
        String uri = args[1]; 
        // add schema if not present
        if (!uri.contains("://")) {
            uri = "coaps://" + uri;
        }
        if (uri.endsWith("/")) {
            uri = uri.substring(-1);
        }

        
        switch (testcase) {
        case 1 : //Unauthorized Resource Request 1.
            System.out.println("=====Starting Test 1.======");
            Connector c = new UDPConnector();
            CoapEndpoint e = new CoapEndpoint.CoapEndpointBuilder().setConnector(c)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();
            uri = uri.replace("coaps:", "coap:");
            uri = uri + "/"; 
            CoapClient client = new CoapClient(uri);
            client.setEndpoint(e);   
            try {
                c.start();
            } catch (IOException ex) {
                LOGGER.severe("Failed to start Connector: " 
                        + ex.getMessage());
                throw new AceException(ex.getMessage());
            }
                   LOGGER.finest("Sending request");
            CoapResponse res = client.get();
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            System.out.println(CBORObject.DecodeFromBytes(
                    res.getPayload()).toString());
            System.out.println("=====End Test 1.======");
            return;
        case 2 : //Token Endpoint Test 2.1
            System.out.println("=====Starting Test 2.1======");
            c = new UDPConnector();
            e = new CoapEndpoint.CoapEndpointBuilder().setConnector(c)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();
            uri = uri.replace("coaps:", "coap:");
            uri = uri + "/token";
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
            CBORObject payload = CBORObject.FromObject("blah");
            res = client.post(payload.EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            System.out.println(Constants.unabbreviate(
                    CBORObject.DecodeFromBytes(res.getPayload())));
            System.out.println("=====End Test 2.1======");
            return;
        case 3 : //Token Endpoint Test 2.2
            System.out.println("=====Starting Test 2.2======");
            DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
            builder.setAddress(new InetSocketAddress(0));
            builder.setIdentity(rpk.AsPrivateKey(), 
                    rpk.AsPublicKey());
            builder.setSupportedCipherSuites(new CipherSuite[]{
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
            builder.setClientAuthenticationRequired(false);        
            DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
            CoapEndpointBuilder ceb = new CoapEndpointBuilder();
            ceb.setConnector(dtlsConnector);
            ceb.setNetworkConfig(NetworkConfig.getStandard());
            e = ceb.build();
            uri = uri + "/token";
            client = new CoapClient(uri);
            client.setEndpoint(e);
            dtlsConnector.start();
            Map<Short, CBORObject> params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("/ace-echo"));
            params.put(Constants.AUD, CBORObject.FromObject("coap://localhost"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            CBORObject resP = CBORObject.DecodeFromBytes(res.getPayload());
            System.out.println(Constants.unabbreviate(resP));
            System.out.println("=====End Test 2.2======");
            return;
        case 4 : //Token Endpoint Test 2.3
            System.out.println("=====Starting Test 2.3======");
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
            uri = uri + "/token";
            client = new CoapClient(uri);
            client.setEndpoint(e);
            dtlsConnector.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("/ace-echo"));
            //params.put(Constants.AUD, CBORObject.FromObject("rs1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            resP = CBORObject.DecodeFromBytes(res.getPayload());
            System.out.println(Constants.unabbreviate(resP));
            System.out.println("=====End Test 2.3======");
        case 5 : //Token Endpoint Test 2.4
            System.out.println("=====Starting Test 2.4======");
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
            uri = uri + "/token";
            client = new CoapClient(uri);
            client.setEndpoint(e);
            dtlsConnector.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            //params.put(Constants.SCOPE, 
            //        CBORObject.FromObject("/ace-echo"));
            params.put(Constants.AUD, CBORObject.FromObject("rs1"));
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            resP = CBORObject.DecodeFromBytes(res.getPayload());
            System.out.println(Constants.unabbreviate(resP));
            System.out.println("=====End Test 2.4======");
        case 6 : //Token Endpoint Test 2.5
            System.out.println("=====Starting Test 2.5======");
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
            uri = uri + "/token";
            client = new CoapClient(uri);
            client.setEndpoint(e);
            dtlsConnector.start();
            params = new HashMap<>();
            params.put(Constants.GRANT_TYPE, Token.clientCredentials);
            params.put(Constants.SCOPE, 
                    CBORObject.FromObject("HelloWorld"));
            params.put(Constants.AUD, CBORObject.FromObject("rs1"));
            CBORObject cnf = CBORObject.NewMap();
            cnf.Add(Constants.COSE_KEY, psk.AsCBOR());
            params.put(Constants.CNF, cnf);
            res = client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    MediaTypeRegistry.APPLICATION_CBOR);   
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());
            resP = CBORObject.DecodeFromBytes(res.getPayload());
            System.out.println(Constants.unabbreviate(resP));
            System.out.println("=====End Test 2.5======");
        case 7 : //Token Endpoint Test 2.6
        case 8 : //Token Endpoint Test 2.7
        case 9 : //Token Endpoint Test 2.8
        case 10 : //Token Endpoint Test 2.9
        case 11 : //Token Endpoint Test 2.10
        case 12 : //Token Endpoint Test 2.11
        case 13 : //Introspection Endpoint Test 3.1
        case 14 : //Introspection Endpoint Test 3.2
        case 15 : //Introspection Endpoint Test 3.3
        case 16 : //Introspection Endpoint Test 3.4
        case 17 : //Authorization Information Endpoint Test 4.1
        case 18 : //Authorization Information Endpoint Test 4.2  
        case 19 : //Authorization Information Endpoint Test 4.3      
        case 20 : //Authorization Information Endpoint Test 4.4     
        case 21 : //Authorization Information Endpoint Test 4.5 
        case 22 : //Access Request Test 5.1
        case 23 : //Access Request Test 5.2
        case 24 : //Access Request Test 5.3
        case 25 : //Access Request Test 5.4
        case 26 : //Access Request Test 5.5
        default:
            break;
            
        }        
    }

}
