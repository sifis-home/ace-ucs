package se.sics.ace.interop;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
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

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;

/**
 * @author Ludwig Seitz
 *
 */
public class PlugtestClient {

    /**
     * 
     */
    public PlugtestClient() {
        // TODO Auto-generated constructor stub
    }
    
    private static byte[] key128 =
        {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
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
        
        int testcase = Integer.parseInt(args[0]);
        String otherAddr = args[1]; 
        
        switch (testcase) {
        case 1 : //Unauthorized Resource Request 1.
            System.out.println("=====Starting Test 1.======");
            Connector c = new UDPConnector();
            CoapEndpoint e = new CoapEndpoint.CoapEndpointBuilder().setConnector(c)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();
            CoapClient client = new CoapClient(otherAddr);
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
            System.out.println(
                    CBORObject.DecodeFromBytes(res.getPayload()).toString());
            System.out.println("=====End Test 1.======");
            return;
        case 2 : //Token Endpoint Test 2.1
            System.out.println("=====Starting Test 2.======");
            c = new UDPConnector();
            e = new CoapEndpoint.CoapEndpointBuilder().setConnector(c)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();
            client = new CoapClient(otherAddr);
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
            System.out.println(
                    CBORObject.DecodeFromBytes(res.getPayload()).toString());
            System.out.println("=====End Test 1.======");
            return;
        case 3 : //Token Endpoint Test 2.2
        case 4 : //Token Endpoint Test 2.3
        case 5 : //Token Endpoint Test 2.4
        case 6 : //Token Endpoint Test 2.5
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
        
        OneKey asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("Client1", key128));
        builder.setIdentity(asymmetricKey.AsPrivateKey(), 
                asymmetricKey.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
//                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
       
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpointBuilder ceb = new CoapEndpointBuilder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("/ace-echo"));
        params.put(Constants.AUD, CBORObject.FromObject("coap://localhost"));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        
    }

}
