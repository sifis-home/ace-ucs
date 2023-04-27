package se.sics.ace.performance.introspection;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.rs.AsRequestCreationHints;

import java.io.IOException;
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
 * This test verifies that a token can be used to retrieve different protected resources
 * Also, it tests the interaction between the client and both the servers.
 *
 * Procedure:
 * 1) Run the AceAS.java
 * 2) Run the AceRS.java
 * 3) Run the OscoreProtocolCTestServer.java
 *
 *  Test explained:
 *  The Client "clientA" makes a token request to AS. It asks for the scope "r_temp w_temp r_helloWorld foobar" (that
 *  identifies the resources "r_temp", "w_temp", "r_helloWorld",and "foobar") at the RS "rs1".
 *  AS generates a token for the allowed resources, i.e., "r_temp", "w_temp", and "r_helloWorld", and sends the scope
 *  "r_temp w_temp r_helloWorld" to the client together with other claims.
 *
 *  The client posts the token, a nounce N1, and its own OSCORE recipient Id ID1 to the authz-info endpoint at the RS.
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

public class PerfIntroC2 {

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
    private static byte[] idContext = new byte[] {0x44};

    private static List<Set<Integer>> usedRecipientIds = new ArrayList<>();

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    private static int denialsCount = 0;

    public PerfIntroC2(String id, byte[] key128, Integer port){

        PerfIntroC2.clientId = id;

        if (key128 != null)
            PerfIntroC2.key128 = key128;

        if (port != null)
            PerfIntroC2.RS_COAP_PORT = port;
    }

    public static void main(String[] args) throws Exception {

        // initialize OSCORE context
        ctx = new OSCoreCtx(key128, true, null,
                new byte[] {0x22}, // client identity
                new byte[] {0x33}, // AS identity
                null, null, null, idContext, MAX_UNFRAGMENTED_SIZE);

        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();

        for (int i = 0; i < 4; i++) {
            // Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
            // The set with index 0 refers to Sender IDs with size 1 byte
            usedRecipientIds.add(new HashSet<>());
        }

        System.out.println("\n--------STARTING COMMUNICATION WITH AS--------\n");

        // 1. Make Access Token request to the /token endpoint
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

        // 2. Post the Access Token to the /authz-info endpoint at the RS
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost:" + RS_COAP_PORT + "/authz-info", response, ctxDB, usedRecipientIds);

        System.out.println("\n--------COMMUNICATION WITH RS ENDED (1)------\n");

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));

//        doGetRequest("helloWorld");
//        doGetRequest("temp");
//        doPostRequest("temp", "22.0 C");

        // 3. Make GET and POST requests to access the resources
        RequestMaker requestMaker = new RequestMaker();
        requestMaker.run();



        // after having received many UNAUTHZ responses from the RS, the Client asks the AS a new token.
        response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx, ctxDB);

        resAs = CBORObject.DecodeFromBytes(response.getPayload());
        map = Constants.getParams(resAs);
        System.out.println(map);

    }


    public static CoapResponse doGetRequest(String resource)
            throws OSException, ConnectorException, AceException, IOException {

        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost:" + RS_COAP_PORT + "/" + resource, RS_COAP_PORT), ctxDB);

        Request req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        return c.advanced(req);
    }


   public static CoapResponse doPostRequest(String resource, String payload)
           throws OSException, ConnectorException, AceException, IOException {

       CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost:" + RS_COAP_PORT + "/" + resource, RS_COAP_PORT), ctxDB);

       Request req = new Request(CoAP.Code.POST);
       req.getOptions().setOscore(new byte[0]);
       req.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
       CBORObject payloadCbor  = CBORObject.FromObject(payload);
       req.setPayload(payloadCbor.EncodeToBytes());
       return c.advanced(req);
   }

   public static class RequestMaker implements Runnable {


       @Override
       public void run() {
           int count = 0;
           int randomTemp;

           CoapResponse res = null;
           while(true) {
               if (count%4 != 0) {
                   try {
                       res = doGetRequest("temp");
                   } catch(AceException | OSException | ConnectorException | IOException e) {
                       e.printStackTrace();
                   }

               }
               else {
                   randomTemp = (int)(Math.random()*100);
                   try {
                       res = doPostRequest("temp", randomTemp + ".0 C");
                   } catch(AceException | OSException | ConnectorException | IOException e) {
                       e.printStackTrace();
                   }
               }
               if (res.getCode().isSuccess()) {
                   // print response code and the message from the RS
                   System.out.println("\nResponse Code:       " + res.getCode() + " - " + res.advanced().getCode().name());
                   System.out.println("Response Message:      " + res.getResponseText() + "\n");
               }
               else if (res.getCode().isServerError() || res.getCode().isClientError()) {
                   CBORObject payload = CBORObject.DecodeFromBytes(res.getPayload());
                   Map<Short, CBORObject> hintsMap = AsRequestCreationHints.parseHints(payload);
                   System.out.println("AS Request Creation Hints: " + hintsMap);
                   //System.exit(1);
                   denialsCount++;
                   if (denialsCount == 5) {
                       denialsCount = 0;
                       //throw new AceException("Too many denials")
                       break;
                   }
               }
               count++;
               try {
                   sleep(3000);
               } catch (InterruptedException e) {
                   e.printStackTrace();
               }
           }
       }
   }
}

