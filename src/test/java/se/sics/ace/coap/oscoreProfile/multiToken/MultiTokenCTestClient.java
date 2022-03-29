package se.sics.ace.coap.oscoreProfile.multiToken;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TrlStore;
import se.sics.ace.Util;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.BasicTrlStore;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.TrlResponses;

import java.util.*;
import java.util.logging.Logger;

import static java.lang.Thread.sleep;

/**
 * This test verifies the diff query mode.
 * First, the client makes 7 token requests for 7 different resource server, so that
 * it obtains 7 different tokens.
 * Then, it makes an observe request with the query parameter 'diff' with value 2.
 * This means that the AS will return the latest 2 diff entries added to the CBOR
 * array containing all the diff entries pertaining to this peer.
 * All the policies giving PERMIT at the UCS have the same mutable attribute
 * (dummy_env_attribute).
 * After 15 seconds (from the start of the AS), the value of dummy_env_attribute
 * is changed, and this triggers the revocation of all the tokens.
 * The client receives a notification each time its portion of the trl changes.
 *
 * nMax is set to 3 at the AS. However, we specified 'diff=2', so we expect that
 * the number of diff queries received at each notification is at most 2.
 * Also, we print the local trl and see that it grows correctly.
 *
 * Then, the client makes some diff-query requests by specifying the cursor.
 * It tries with values from 3 to 8.
 * We verify that each received response is compliant with what expected.
 *
 * @author Marco Rasori
 */

public class MultiTokenCTestClient {

    /**
     * The logger
     */
    private static final Logger LOGGER
        = Logger.getLogger(MultiTokenCTestClient.class.getName());

    /**
     * Client name
     */
    public static String clientId = "clientA";

    /**
     * Symmetric key shared with the authorization server and used for the OSCORE context
     */
    static byte[] key128 = {'C', '-', 'A', 'S', ' ', 'P', 'S', 'K', 9, 10, 11, 12, 13, 14, 15, 16};


    private static OSCoreCtx ctx;

    private static OSCoreCtxDB ctxDB;

    private static List<Set<Integer>> usedRecipientIds = new ArrayList<>();

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    private static Map<String,String> validTokens = new HashMap<>();




    public MultiTokenCTestClient(String id, byte[] key128){

        MultiTokenCTestClient.clientId = id;

        if (key128 != null)
            MultiTokenCTestClient.key128 = key128;

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

        for (int i = 1 ; i <= 7; i++) {
            // 1. Make Access Token request to the /token endpoint
            CBORObject params;
            params = GetToken.getClientCredentialsRequest(
                    CBORObject.FromObject("rs"+i),
                    CBORObject.FromObject("r_temp"), null);

            Response asRes = OSCOREProfileRequests.getToken(
                    client4AS, asAddr + "/token", params);

            System.out.println("\n---------COMMUNICATION WITH AS ENDED----------\n");
            CBORObject resAs = CBORObject.DecodeFromBytes(asRes.getPayload());
            Map<Short, CBORObject> map = Constants.getParams(resAs);
            System.out.println(map);

            // pretend that the access token has been posted, and add it
            // to the valid tokens.
            validTokens.put(Util.computeTokenHash(map.get(Constants.ACCESS_TOKEN)), "rs"+i);
        }

        TrlStore trlStore = new BasicTrlStore();


        String trlAddr = "/trl?diff=3";

        // uncomment for observe
        // 2. Make Observe request to the /trl endpoint
        ClientCoapHandler handler = new ClientCoapHandler(trlStore);
        CoapObserveRelation relation =
                OSCOREProfileRequests.makeObserveRequest(
                        client4AS, asAddr + trlAddr, handler);

        sleep(30000);
        // make poll requests

        // cursor = 3
        // obsolete value, should obtain 2.05 with Empty,True,Null
        CoapResponse responseTrl =
                OSCOREProfileRequests.makePollRequest(
                        client4AS, asAddr + "/trl?diff=0&cursor=3");
        CBORObject payload = TrlResponses.checkAndGetPayload(responseTrl);
        assert(payload.get(Constants.DIFF_SET).getType().equals(CBORType.Array));
        assert(payload.get(Constants.DIFF_SET).size() == 0);
        assert(payload.get(Constants.MORE).equals(CBORObject.True));
        assert(payload.get(Constants.CURSOR).equals(CBORObject.Null));


        sleep(2000);
        // cursor = 4
        // should obtain all the diff entries in the diffSet (from 5 to 7).
        responseTrl =
                OSCOREProfileRequests.makePollRequest(
                        client4AS, asAddr + "/trl?diff=0&cursor=4");
        payload = TrlResponses.checkAndGetPayload(responseTrl);
        assert(payload.get(Constants.DIFF_SET).getType().equals(CBORType.Array));
        assert(payload.get(Constants.DIFF_SET).size() == 3);
        assert(payload.get(Constants.MORE).equals(CBORObject.False));
        assert(payload.get(Constants.CURSOR).AsNumber().ToInt32Checked() == 7);


        sleep(2000);
        // cursor = 5
        // should obtain 2 out of 3 diff entries in the diffSet (from 6 to 7).
        responseTrl =
                OSCOREProfileRequests.makePollRequest(
                        client4AS, asAddr + "/trl?diff=0&cursor=5");
        payload = TrlResponses.checkAndGetPayload(responseTrl);
        assert(payload.get(Constants.DIFF_SET).getType().equals(CBORType.Array));
        assert(payload.get(Constants.DIFF_SET).size() == 2);
        assert(payload.get(Constants.MORE).equals(CBORObject.False));
        assert(payload.get(Constants.CURSOR).AsNumber().ToInt32Checked() == 7);


        sleep(2000);
        // cursor = 6
        // should obtain 1 out of 3 diff entries in the diffSet (only 7).
        responseTrl =
                OSCOREProfileRequests.makePollRequest(
                        client4AS, asAddr + "/trl?diff=0&cursor=6");
        payload = TrlResponses.checkAndGetPayload(responseTrl);
        assert(payload.get(Constants.DIFF_SET).getType().equals(CBORType.Array));
        assert(payload.get(Constants.DIFF_SET).size() == 1);
        assert(payload.get(Constants.MORE).equals(CBORObject.False));
        assert(payload.get(Constants.CURSOR).AsNumber().ToInt32Checked() == 7);


        sleep(2000);
        // cursor = 7
        // should obtain 0 out of 3 diff entries in the diffSet.
        // So, an Empty CBOR array, cursor=7, more=False
        responseTrl =
                OSCOREProfileRequests.makePollRequest(
                        client4AS, asAddr + "/trl?diff=0&cursor=7");
        payload = TrlResponses.checkAndGetPayload(responseTrl);
        assert(payload.get(Constants.DIFF_SET).getType().equals(CBORType.Array));
        assert(payload.get(Constants.DIFF_SET).size() == 0);
        assert(payload.get(Constants.MORE).equals(CBORObject.False));
        assert(payload.get(Constants.CURSOR).AsNumber().ToInt32Checked() == 7);


        sleep(2000);
        // cursor = 8
        // should obtain 4.00 out of bounds
        responseTrl = OSCOREProfileRequests.makePollRequest(
                client4AS, asAddr + "/trl?diff=0&cursor=8");
        Map<Short, CBORObject> errorMap = TrlResponses.getErrorMap(responseTrl);
        assert(errorMap.containsKey(Constants.TRL_ERROR));
        assert(errorMap.get(Constants.TRL_ERROR).AsNumber().ToInt32Checked()
                == Constants.OUT_OF_BOUND_CURSOR_VALUE);
        LOGGER.info("Cursor = 8. Got error: " + errorMap.get(Constants.TRL_ERROR_DESCRIPTION).AsString());

        while(true)
            sleep(1000);

    }



    public static void terminateActiveButRevokedSessions(TrlStore trlStore) {

        Set<String> trl = trlStore.getLocalTrl();
        Set<String> intersection = new HashSet<>(validTokens.keySet());
        intersection.retainAll(trl);

        for (String th : intersection) {
            // pretend to have removed the Oscore context with the rs
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
                CBORObject payload = TrlResponses.checkAndGetPayload(response);

                System.out.println("\nReceived diff set array contains "
                        + payload.get(Constants.DIFF_SET).size() + " diff entries");

                TrlResponses.processResponse(response, trlStore);
                terminateActiveButRevokedSessions(trlStore);

                System.out.println("\nLocal Trl (size: " + trlStore.getLocalTrl().size() + ") : "
                        + trlStore.getLocalTrl());

                System.out.println("\nValid tokens (size: " + validTokens.size() + ") : "
                        + validTokens.keySet() + "\n");


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
