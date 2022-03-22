package se.sics.ace.coap.oscoreProfile.observe;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.TrlResponses;
import se.sics.ace.coap.client.BasicTrlStore;
import se.sics.ace.TrlStore;
import se.sics.ace.rs.AsRequestCreationHints;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.logging.Logger;


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
 * Finally, it tests the notification mechanism through a request to the trl endpoint.
 * The client sends an Observe request, and the AS replies with the list of revoked
 * tokens for this client.
 * Each time a token pertaining to this client is inserted or removed from the trl (token
 * revocation list), the AS sends to the client the list of tokens in the trl that pertain
 * to this client.
 *
 * Procedure:
 * 1) Run the OscoreProtObserveASTestServer.java
 * 2) Run the OscoreProtObserveRSTestServer.java
 * 3) Run the OscoreProtObserveCTestServer.java
 *
 *  Test explained:
 *  First, the Client "clientA" makes a request to the AS to observe the trl.
 *  Then, clientA makes a token request to AS. It asks for the scope "r_temp w_temp r_helloWorld foobar" (that
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

public class OscoreProtObserveCTestClient {

    /**
     * The logger
     */
    private static final Logger LOGGER
        = Logger.getLogger(OscoreProtObserveCTestClient.class.getName());

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

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    private static Map<String,String> validTokens = new HashMap<>();




    public OscoreProtObserveCTestClient(String id, byte[] key128, Integer port){

        OscoreProtObserveCTestClient.clientId = id;

        if (key128 != null)
            OscoreProtObserveCTestClient.key128 = key128;

        if (port != null)
            OscoreProtObserveCTestClient.RS_COAP_PORT = port;
    }

    public static void main(String[] args) throws Exception {

        byte[] senderId = new byte[]{0x22};     // client identity
        byte[] recipientId = new byte[]{0x33};  // AS identity
        byte[] contextId = new byte[] {0x44};   // C-AS context ID (hardcoded)
        // initialize OSCORE context
        ctx = new OSCoreCtx(key128, true, null,
                senderId, recipientId,null, null,
                null, contextId, MAX_UNFRAGMENTED_SIZE);

        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();

        for (int i = 0; i < 4; i++) {
            // Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
            // The set with index 0 refers to Sender IDs with size 1 byte
            usedRecipientIds.add(new HashSet<>());
        }

        System.out.println("\n--------STARTING COMMUNICATION WITH AS--------\n");

        String asAddr = "coap://localhost";
        CoapClient client4AS = OSCOREProfileRequests.buildClient(asAddr, ctx, ctxDB);
        TrlStore trlStore = new BasicTrlStore();


        // FULL_QUERY: trlAddr=/trl
        // DIFF_QUERY: trlAddr=/trl?pmax=10&foo=bar&diff=3
        String trlAddr = "/trl";

        // uncomment for observe
        // 1. Make Observe request to the /trl endpoint
        ClientCoapHandler handler = new ClientCoapHandler(trlStore);
        CoapObserveRelation relation =
                OSCOREProfileRequests.makeObserveRequest(
                        client4AS, asAddr + trlAddr, handler);

        // uncomment for polling
        // 1. Make poll request to the /trl endpoint
//        CoapResponse responseTrl =
//                OSCOREProfileRequests.makePollRequest(
//                        client4AS, asAddr + trlAddr);
//        TrlResponses.processResponse(responseTrl, trlStore); //, mode);
//        terminateActiveButRevokedSessions(trlStore);

        // 2. Make Access Token request to the /token endpoint
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs1"),
                CBORObject.FromObject("r_temp w_temp r_helloWorld foobar"), null);

        Response asRes = OSCOREProfileRequests.getToken(
                client4AS, asAddr + "/token", params);


        System.out.println("\n---------COMMUNICATION WITH AS ENDED----------\n");

        CBORObject resAs = CBORObject.DecodeFromBytes(asRes.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(resAs);
        System.out.println(map);
        assert (map.containsKey(Constants.ACCESS_TOKEN));
        assert (!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert (map.containsKey(Constants.SCOPE));
        assert (map.get(Constants.SCOPE).AsString().equals("r_temp w_temp r_helloWorld"));


        System.out.println("\n------STARTING COMMUNICATION WITH RS (1)----\n");

        // 3. Post the Access Token to the /authz-info endpoint at the RS
        Response rsRes = null;
        String rsAddr = "coap://localhost:" + RS_COAP_PORT;
        try{
            rsRes = OSCOREProfileRequests.postToken(
                    rsAddr + "/authz-info", asRes, ctxDB, usedRecipientIds);
        } catch (AceException e) {
            LOGGER.severe("Failed posting token to RS: " + e.getMessage());
            System.exit(1);
        }

        if (rsRes.getCode().equals(CoAP.ResponseCode.CREATED)) {
            validTokens.put(Util.computeTokenHash(map.get(Constants.ACCESS_TOKEN)), rsAddr);
        }

        System.out.println("\n--------COMMUNICATION WITH RS ENDED (1)------\n");

//        doGetRequest("helloWorld");
//        doGetRequest("temp");
//        doPostRequest("temp", "22.0 C");

        // 4. Make GET and POST requests to access the resources
        CoapClient client4RS = OSCOREProfileRequests.getClient(
                new InetSocketAddress(rsAddr, RS_COAP_PORT), ctxDB);

        client4RS.setURI(rsAddr + "/temp");

        int count = 0;
        int randomTemp;
        CoapResponse res;
        while(validTokens.containsValue(rsAddr)) { // FIXME: this check should be done against the presence of
                                                   //        context in the OscoreCtxDB. However, when I remove
                                                   //        the ctx through ctxDB.removeContext(ctx), the context
                                                   //        remains in the uriMap of the database. Therefore,
                                                   //        if I check ctxDB.getContext(rsAddr) != null, the context
                                                   //        is still there, and the while loop cannot terminate.
                                                   //        I would call the getContext(recipientID), but I cannot
                                                   //        since the recipientID is assigned within the postToken
                                                   //        method.
            if (count%4 != 0) {
                //res = doGetRequest("temp");
                res = doGetRequest(client4RS);
            }
            else {
                randomTemp = (int)(Math.random()*100);
                //res = doPostRequest("temp", randomTemp + ".0 C");
                res = doPostRequest(client4RS, randomTemp + ".0 C");
            }

            if (res.getCode().isSuccess()) {
                // print response code and the message from the RS
                System.out.println("\nResponse Code:       " + res.getCode() + " - " + res.advanced().getCode().name());
                System.out.println("Response Message:    " + res.getResponseText() + "\n");
            }
            else if (res.getCode().isServerError() || res.getCode().isClientError()) {
                CBORObject payload = CBORObject.DecodeFromBytes(res.getPayload());
                Map<Short, CBORObject> hintsMap = AsRequestCreationHints.parseHints(payload);
                System.out.println("AS Request Creation Hints: " + hintsMap);
                System.exit(1);
            }

            count++;
            sleep(5000);
        }
        System.out.println("Client terminated");

    }



    public static CoapResponse doGetRequest(CoapClient client) throws Exception {

        Request req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        return client.advanced(req);
    }


    public static CoapResponse doPostRequest(CoapClient client, String payload) throws Exception{

        Request req = new Request(CoAP.Code.POST);
        req.getOptions().setOscore(new byte[0]);
        req.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
        CBORObject payloadCbor  = CBORObject.FromObject(payload);
        req.setPayload(payloadCbor.EncodeToBytes());
        return client.advanced(req);
    }

    public static void terminateActiveButRevokedSessions(TrlStore trlStore) {

        Set<String> trl = trlStore.getLocalTrl();
        Set<String> intersection = new HashSet<>(validTokens.keySet());
        intersection.retainAll(trl);

        for (String th : intersection) {
            try {
                // remove ctx associated with the server address
                String srvAddr = validTokens.get(th);
                OSCoreCtx ctxToRemove = ctxDB.getContext(srvAddr);
                ctxDB.removeContext(ctxToRemove);
                // FIXME: this is not working as the removeContext()
                //        does not remove the context from the database entirely.
                //        Waiting for a fix within Californium...
            } catch (OSException e) {
                e.printStackTrace();
            }
            validTokens.remove(th);
        }
    }

    public static class ClientCoapHandler implements CoapHandler {

        private final TrlStore trlStore;

        public ClientCoapHandler(TrlStore trlStore) {

            this.trlStore = trlStore;
        }

        @Override public void onLoad(CoapResponse response) {
            try {
                TrlResponses.processResponse(response, trlStore);
                terminateActiveButRevokedSessions(trlStore);

            } catch (AssertionError | AceException error) {
                LOGGER.severe("Assert:" + error);
            }
            System.out.println("NOTIFICATION: " + response.advanced());
        }

        @Override public void onError() {
            System.err.println("OBSERVE FAILED");
        }
    }
}
