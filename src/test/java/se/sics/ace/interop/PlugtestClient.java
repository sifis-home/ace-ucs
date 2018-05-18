package se.sics.ace.interop;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.CoapEndpointBuilder;
import org.eclipse.californium.core.network.config.NetworkConfig;
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

public class PlugtestClient {

    public PlugtestClient() {
        // TODO Auto-generated constructor stub
    }
    
    private static byte[] key128 =
        {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    public static void main(String[] args) throws CoseException, IOException, AceException {
        OneKey asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientA", key128));
        builder.setIdentity(asymmetricKey.AsPrivateKey(), 
                asymmetricKey.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
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
