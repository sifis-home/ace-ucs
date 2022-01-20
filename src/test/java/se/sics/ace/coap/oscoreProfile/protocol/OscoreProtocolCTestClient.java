package se.sics.ace.coap.oscoreProfile.protocol;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;

import java.net.InetSocketAddress;
import java.util.*;

import static java.lang.Thread.sleep;
/*
        C                            RS                  AS
        |                            |                    |
        | ----- POST /token ----------------------------> |
        |                            |                    |
        | <--------------------------- Access Token ----- |
        |                            + Access Information |
        | ---- POST /authz-info ---> |                    |
        |   (access_token, N1, ID1)  |                    |
        |                            |                    |
        | <- 2.01 Created (N2, ID2)- |                    |
        |                            |                    |
      /Sec Context             /Sec Context               |
        derivation/              derivation/              |
        |                            |                    |
        | ---- OSCORE Request -----> |                    |
        |                            |                    |
        |                    /proof-of-possession         |
        |                    Sec Context storage/         |
        |                            |                    |
        | <--- OSCORE Response ----- |                    |
        |                            |                    |
     /proof-of-possession            |                    |
     Sec Context storage/            |                    |
        |                            |                    |
        | ---- OSCORE Request -----> |                    |
        |                            |                    |
        | <--- OSCORE Response ----- |                    |
        |                            |                    |
        |           ...              |                    |

                        Protocol overview

 */

/**
 * This test verifies that a token with multiple scopes can be used to retrieve different protected resources
 * Also, it tests the interaction between the client and both the servers.
 *
 * Procedure:
 * 1) Run the OscoreProtocolASTestServer.java
 * 2) Run the OscoreProtocolRSTestServer.java
 * 3) Run the OscoreProtocolCTestServer.java
 *
 *  Test explained:
 *  clientA makes a token request to AS. It asks for the scopes "r_temp w_temp r_helloWorld foobar" at the RS "rs1".
 *  AS generates a token for the allowed scopes, i.e., r_temp, w_temp and r_helloWorld, and sends it to the client
 *  together with other claims.
 *  The client posts the token, a nounce N1, and its own OSCORE recipient Id ID1 to authz-info endpoint.
 *  The RS replies with a nounce N2 and the OSCORE sender Id ID2 (from client point of view, ID2 is the sender ID).
 *  The client sets the URI specifying the resource (e.g., "coap://localhost:" + RS_COAP_SECURE_PORT + "/temp")
 *  and makes the request.
 *  The request might be either a GET, to obtain the reading of a protected resource, or a POST, to modify the value of
 *  the protected resource.
 *  This test loops, making three GET requests and then one POST request. Each request happens after three seconds form
 *  the previous request.
 *
 *  Note that, since we are making the test on the localhost, AS and RS CoAP ports must be different.
 *  RS port is set to 5685, while AS uses the default CoAP port (5683) and secure port (5684).
 *
 * @author Marco Rasori
 */

public class OscoreProtocolCTestClient {

    /**
     * Client name
     */
    public static String clientId = "clientA";

    /**
     * Symmetric key shared with the authorization server and used for the OSCORE context
     */
    static byte[] key128 = {'C', '-', 'A', 'S', ' ', 'P', 'S', 'K', 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * Resource Server CoAP port.
     * The resource server does not use the standard port
     * since the authorization server is using it
     */
    public static int RS_COAP_PORT = 5685;

    private static OSCoreCtx ctx;

    private static OSCoreCtxDB ctxDB;

    private static List<Set<Integer>> usedRecipientIds = new ArrayList<>();

    public OscoreProtocolCTestClient(String id, byte[] key128, Integer port){

        OscoreProtocolCTestClient.clientId = id;

        if (key128 != null)
            OscoreProtocolCTestClient.key128 = key128;

        if (port != null)
            OscoreProtocolCTestClient.RS_COAP_PORT = port;
    }

    public static void main(String[] args) throws Exception {

        // initialize OSCORE context
        ctx = new OSCoreCtx(key128, true, null,
                new byte[] {0x22}, // client identity
                new byte[] {0x33}, // AS identity
                null, null, null, null);

        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();

        for (int i = 0; i < 4; i++) {
            // Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
            // The set with index 0 refers to Sender IDs with size 1 byte
            usedRecipientIds.add(new HashSet<>());
        }

        // Client-to-AS request and response

        System.out.println("\n--------STARTING COMMUNICATION WITH AS--------\n");

        // fill params
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs1"),
                CBORObject.FromObject("r_temp w_temp r_helloWorld foobar"), null);

        Response response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx, ctxDB);

        System.out.println("\n---------COMMUNICATION WITH AS ENDED----------\n");

        CBORObject resAs = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(resAs);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp w_temp r_helloWorld"));


        System.out.println("\n------STARTING COMMUNICATION WITH RS (1)----\n");

        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost:" + RS_COAP_PORT + "/authz-info", response, ctxDB, usedRecipientIds);

        System.out.println("\n--------COMMUNICATION WITH RS ENDED (1)------\n");

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));

//        doGetRequest("helloWorld");
//        doGetRequest("temp");
//        doPostRequest("temp", "22.0 C");

        int count = 0;
        int randomTemp;
        CoapResponse res;
        while(true) {
            if (count%4 != 0) {
                res = doGetRequest("temp");
            }
            else {
                randomTemp = (int)(Math.random()*100);
                res = doPostRequest("temp", randomTemp + ".0 C");
            }
            // print response code and the message from the RS
            System.out.println("\nResponse Code:       " + res.getCode() + " - " + res.advanced().getCode().name());
            System.out.println(  "Response Message  :  " + res.getResponseText() + "\n");

            if (!CoAP.ResponseCode.isSuccess(res.advanced().getCode())){
                System.out.println("Received an error code. Terminating.");
                return;
            }
            count++;
            sleep(3000);
        }

    }


    public static CoapResponse doGetRequest(String resource) throws Exception {

        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost:" + RS_COAP_PORT + "/" + resource, RS_COAP_PORT), ctxDB);

        Request req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        return c.advanced(req);
    }


   public static CoapResponse doPostRequest(String resource, String payload) throws Exception {

       CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost:" + RS_COAP_PORT + "/" + resource, RS_COAP_PORT), ctxDB);

       Request req = new Request(CoAP.Code.POST);
       req.getOptions().setOscore(new byte[0]);
       req.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
       CBORObject payloadCbor  = CBORObject.FromObject(payload);
       req.setPayload(payloadCbor.EncodeToBytes());
       return c.advanced(req);
   }

}

