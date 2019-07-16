package se.sics.ace.oscore.group;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;
import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.MessageTag;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * A test case for the OSCORE profile interactions between client and server.
 * 
 * This client can be used for doing Group Joining over OSCORE.
 * Posts a Token to the GM followed by the group join procedure.
 * 
 * This should be run with TestOSCoreRSGroupOSCORE as server.
 * 
 * For testing with Peter van der Stok.
 * 
 * @author Ludwig Seitz, Rikard Höglund & Marco Tiloca
 *
 */
public class OSCoreClientGroupOSCORE {

	//Sets the port to use
	private final static int GM_PORT = CoAP.DEFAULT_COAP_PORT;
	//Set the hostname/IP of the RS (GM)
	private final static String GM_ADDRESS = "localhost";
	
	private static String GM_HOST;
	
    /**
     * The cnf key used in these tests
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    @SuppressWarnings("unused")
	private static OSCoreCtx osctx;
    
    public static void main(String[] args) throws Exception {
    	OSCoreCoapStackFactory.useAsDefault();
    	
    	GM_HOST = GM_ADDRESS + ":" + GM_PORT;
    	
    	setUp();
    
    	testSuccess();
    }
    

    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    public static void setUp() throws OSException {
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnf, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null);
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    public static void testSuccess() throws Exception {
        //Generate a token and simulated response from As
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = "clientA".getBytes(Constants.charset);
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, keyCnf);
        byte[] serverId = "rs1".getBytes(Constants.charset);
        osc.Add(Constants.OS_SERVERID, serverId);

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
        //Post the Token to GM
        System.out.println("Posting Token to GM at " + "coap://" + GM_HOST + "/authz-info");
        System.out.println("Simulated response from AS used: " + payload.ToJSONString());
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://" + GM_HOST + "/authz-info", asRes);
        System.out.println("GM Response to Token post: " + Utility.arrayToString(rsRes.getPayload()));
       
        System.out.println("Due to Token post the following OSCORE Context has been generated:");
        OSCoreCtx generatedContext = HashMapCtxDB.getInstance().getContext("coap://" + GM_HOST + "/helloWorld");
        Utility.printContextInfo(generatedContext);
        
		//Submit a request to GM
		System.out.println("Performing request to GM at " + "coap://" + GM_HOST + "/helloWorld" + " (port " + GM_PORT + ")");
		CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + GM_HOST + "/helloWorld", GM_PORT));
		Request helloReq = new Request(CoAP.Code.GET);
		helloReq.getOptions().setOscore(new byte[0]);
		CoapResponse helloRes = c.advanced(helloReq);
		System.out.println("Received response from GM:" + helloRes.getResponseText());

       
    }

    
    

}
