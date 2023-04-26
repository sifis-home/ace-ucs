package se.sics.ace.performance;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import se.sics.ace.*;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.BasicTrlStore;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.TrlResponses;
import se.sics.ace.examples.KissTime;
import se.sics.ace.rs.AsRequestCreationHints;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;

import static java.lang.Thread.sleep;

/**
 * Client to test with AceRS and AceAS
 *
 * @author Marco Rasori
 */

@Command(name = "client",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "Runs an ACE Client.")
public class AceClient implements Callable<Integer> {

    private final static String DEFAULT_ASURI = "localhost:" + CoAP.DEFAULT_COAP_PORT;
    private final static int DEFAULT_RS_PORT = 5685;
    private final static String DEFAULT_RSURI = "localhost:" + DEFAULT_RS_PORT;
    private final static int DEFAULT_MAX_DENIAL = Integer.MAX_VALUE;
    private final static String DEFAULT_AUD = "rs1";
    private final static String DEFAULT_SCOPE = "r_temp r_helloWorld";
    private final static int DEFAULT_POLLING_INTERVAL = 10;
    private final static String DEFAULT_TRL_ADDR = "/trl";
    private final static int DEFAULT_REQUEST_INTERVAL = 1;
    private final static String DEFAULT_SENDER_ID = "0x22";
    private final static String DEFAULT_MASTER_SECRET = "ClientA-AS-MS---";

    @Spec
    CommandSpec spec;

    @Option(names = {"-W", "--WarmUp"},
            required = false,
            description = "Enable warm up, i.e., the Client requests an additional token " +
                    "before performance are recorded. Audience and scope are fixed to 'rs2' " +
                    "and 'r_warmup', respectively.\n" +
                    "Note that the AceAS must be initialized so that the Client has the privileges " +
                    "for such audience and scope.")
    public boolean isWarmUpEnabled = false;

    @Option(names = {"-a", "--asuri"},
            required = false,
            defaultValue = DEFAULT_ASURI,
            description = "The URI of the Authorization Server.\n" +
                    "Hostname and port MUST be specified.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String asUri;

    @Option(names = {"-r", "--rsuri"},
            required = false,
            defaultValue = DEFAULT_RSURI,
            description = "The URI of the Resource Server.\n" +
                    "Hostname and port MUST be specified.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private List<String> rsUri;

    @Option(names = {"-s", "--scope"},
            required = false,
            defaultValue = DEFAULT_SCOPE,
            description = "The scope for which the Client asks the token.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private List<String> scope;

    @Option(names = {"-u", "--audience"},
            required = false,
            defaultValue = DEFAULT_AUD,
            description = "The audience for which the Client asks the token.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private List<String> aud;
    // fixme: we could avoid assigning a default scope and audience.
    //        The Client could not specify them in the request to the AS,
    //        and the AS will use the default audience and scope that it
    //        has for the Client.

    @Option(names = {"-d", "--denials"},
            required = false,
            defaultValue = "" + DEFAULT_MAX_DENIAL,
            description = "The maximum number of 4.01 Unauthorized responses " +
                    "(from the same Resource Server) that the Client is " +
                    "willing to receive before assuming that -- for some reason -- " +
                    "the Resource Server removed its OSCORE Security Context " +
                    "with the Client.\n" +
                    "When this number is reached, the Client asks the Authorization " +
                    "Server a new token with the same audience and scope.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private int denials;

    @Option(names = {"-q", "--requestinterval"},
            required = false,
            defaultValue = "" + DEFAULT_REQUEST_INTERVAL,
            description = "The time interval (in seconds) between two requests " +
                    "to protected resources (at the same Resource Server).\n" +
                    "This interval is independent of the number of resources " +
                    "the Client requests to the Resource Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private int requestInterval;

    @Option(names = {"-m", "--mastersecret"},
            required = false,
            defaultValue = "" + DEFAULT_MASTER_SECRET,
            description = "The symmetric pre-shared key between the Client " +
                    "and the Authorization Server. It is the master secret " +
                    "used for the OSCORE Security Context.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String key;

    @Option(names = {"-x", "--senderid"},
            required = false,
            defaultValue = "" + DEFAULT_SENDER_ID,
            description = "The Sender ID in HEX used for " +
                    "the OSCORE Security Context with the Authorization Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String senderId;

    static class PollingArgs {
        @Option(names = {"-p", "--polling"},
                required = true,
                description = "The Client polls the trl endpoint at the AS.\n")
        boolean polling;

        @Option(names = {"-e", "--interval"},
                required = false,
                defaultValue = "" + DEFAULT_POLLING_INTERVAL,
                description = "The time interval (in seconds) between two polling " +
                        "requests to the trl endpoint.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        int interval;
    }

    static class ObserveArgs {
        @Option(names = {"-o", "--observe"},
                required = true,
                description = "The Client observes the trl endpoint at the AS.\n")
        boolean observe;
    }

    static class TrlAddrArg {
        @Option(names = {"-t", "--trladdress"},
                required = false,
                defaultValue = DEFAULT_TRL_ADDR,
                description = "The address of the trl endpoint, e.g., '/trl'.\n" +
                        "If query parameters are specified, e.g., '/trl?pmax=10&diff=3', " +
                        "the mode is automatically assumed to be 'diff-query'.\n" +
                        "If no query parameters are specified, the mode is assumed to " +
                        "be 'full query'.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String trlAddress;
    }

    static class NotificationArgs {
        @ArgGroup(exclusive = false, multiplicity = "1") PollingArgs pollingArgs;
        @ArgGroup(exclusive = false, multiplicity = "1") ObserveArgs observeArgs;
    }

    static class Args {
        @ArgGroup(exclusive = true, multiplicity = "1") NotificationArgs notification;
        @ArgGroup(exclusive = false) TrlAddrArg trlAddrArg;
    }

    @ArgGroup(exclusive = false) Args args;

    /**
     * Symmetric key shared with the authorization server and used for the OSCORE context
     */
    private static byte[] key128;

    private static OSCoreCtx ctx;
    private static OSCoreCtxDB ctxDB;

    private static List<Set<Integer>> usedRecipientIds = new ArrayList<>();

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    private static final byte[] idContext = new byte[] {0x44};
    private byte[] sId;

    private boolean isPolling = false;
    private boolean isObserve = false;

    private int pollingInterval;

    private String trlAddr;

    private final Set<String> validTokens = new HashSet<>();

//--- MAIN
    public static void main(String[] args) {

        int exitCode = new CommandLine(new AceClient()).execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }


    @Override
    public Integer call() throws Exception {

        parseInputs();

        // initialize OSCORE context
        ctx = new OSCoreCtx(key128, true, null,
                sId, // client identity
                new byte[] {0x33}, // AS identity
                null, null, null, idContext, MAX_UNFRAGMENTED_SIZE);

        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();

        for (int i = 0; i < 4; i++) {
            // Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
            // The set with index 0 refers to Sender IDs with size 1 byte
            usedRecipientIds.add(new HashSet<>());
        }

        CoapClient client4AS = OSCOREProfileRequests.buildClient(asUri, ctx, ctxDB);

        ScheduledExecutorService executorService = null;
        if (isPolling || isObserve) {
            TrlStore trlStore = new BasicTrlStore();

            if (isObserve) {
                // 1. Make Observe request to the /trl endpoint
                ClientCoapHandler handler = new ClientCoapHandler(trlStore);
                CoapObserveRelation relation =
                        OSCOREProfileRequests.makeObserveRequest(
                                client4AS, asUri + trlAddr, handler);
            }

            if (isPolling) {
                // 1. Make poll request to the /trl endpoint
                executorService = Executors
                        .newSingleThreadScheduledExecutor();
                executorService.scheduleAtFixedRate(
                        new Poller(client4AS, asUri + trlAddr, trlStore),
                            pollingInterval, pollingInterval, TimeUnit.SECONDS);
            }
        }

        for (int i = 0; i < rsUri.size(); i++) {
            Integer requester = new Requester(
                    client4AS, rsUri.get(i), aud.get(i), scope.get(i), executorService)
                    .call();
            if (requester == 0)
                return 0;
        }
        return 0;
    }

    class Poller implements Runnable {

        CoapClient client4AS;
        String trlUri;
        TrlStore trlStore;
        public Poller(CoapClient client4AS, String trlUri, TrlStore trlStore) {
            this.client4AS = client4AS;
            this.trlUri = trlUri;
            this.trlStore = trlStore;
        }

        @Override
        public void run() {
            try {
                System.out.println("Now polling:" + new Timestamp(System.currentTimeMillis()));
                CoapResponse responseTrl =
                        OSCOREProfileRequests.makePollRequest(
                                client4AS, trlUri);
                TrlResponses.processResponse(responseTrl, trlStore);
                purgeRevokedTokens(trlStore);
            } catch (AceException e) {
                e.printStackTrace();
            }
        }
    }


    public class ClientCoapHandler implements CoapHandler {

        private final TrlStore trlStore;

        public ClientCoapHandler(TrlStore trlStore) {
            this.trlStore = trlStore;
        }

        @Override public void onLoad(CoapResponse response) {
            try {
                TrlResponses.processResponse(response, trlStore);
                purgeRevokedTokens(trlStore);
            } catch (AssertionError | AceException error) {
                System.out.println("Assert:" + error);
            }
            System.out.println("NOTIFICATION: " + response.advanced());
        }

        @Override public void onError() {
            System.err.println("OBSERVE FAILED");
        }
    }


    public void purgeRevokedTokens(TrlStore trlStore) {

        Set<String> trl = trlStore.getLocalTrl();
        Set<String> intersection = new HashSet<>(validTokens);
        intersection.retainAll(trl);

        synchronized (validTokens) {
            for (String th : intersection) {
                validTokens.remove(th);
            }
            validTokens.notifyAll();
        }
    }


    class Requester implements Callable {

        CoapClient client4AS;
        final CoapClient client4RS;
        String aud;
        String scope;
        String rsAddr;
        int denialsCount = 0;
        /*
         * executorService for the Poller.
         */
        ScheduledExecutorService es;

        public Requester(CoapClient client4AS, String rsAddr, String aud, String scope, ScheduledExecutorService es) {
            this.client4AS = client4AS;
            this.rsAddr = rsAddr;
            this.aud = aud;
            this.scope = scope;
            this.client4RS = new CoapClient(rsAddr);
            this.es = es;
        }

        @Override
        public Integer call() throws Exception {

            int tokenCount = 0;
            TimeProvider time = new KissTime();

            if (isWarmUpEnabled) {
                System.out.println("\n[START] Warm up...");
                // warm up. Ask and obtain a first token to have connections and
                // structures initialized at the AceAS
                Response asRes0;
                try {
                    asRes0 = getToken(client4AS, "rs2", "r_warmup");
                } catch (AceException e) {
                    System.out.println(e.getMessage());
                    client4AS.shutdown();
                    if (es != null) {
                        //Shutting down the Executor Service for the Poller
                        es.shutdown();
                    }
                    System.out.println("Warm up failed. Quitting.");
                    return -1;
                }
                CBORObject resAs0 = CBORObject.DecodeFromBytes(asRes0.getPayload());
                System.out.println("\nResponse from AS");
                System.out.println("Response Code:       " + asRes0.getCode());
                System.out.println("\n[END] Warm up]");
                sleep(500L);
            }

            while(true) {
                String allowedScopes;
                // 1. Get the token
                Response asRes;
                try {
                    tokenCount ++;
                    asRes = getToken(client4AS, aud, scope);
                } catch (AceException e) {
                    System.out.println(e.getMessage());
                    client4AS.shutdown();
                    if (es != null) {
                        //Shutting down the Executor Service for the Poller
                        es.shutdown();
                    }
                    System.out.println("Quitting.");
                    return -1;
                }
                CBORObject resAs = CBORObject.DecodeFromBytes(asRes.getPayload());
                Map<Short, CBORObject> map = Constants.getParams(resAs);
                System.out.println("\nResponse from AS");
                System.out.println("Response Code:       " + asRes.getCode());

                String tokenHash = Util.computeTokenHash(map.get(Constants.ACCESS_TOKEN));
                validTokens.add(tokenHash);
                allowedScopes =
                        map.get(Constants.SCOPE) == null ? scope : map.get(Constants.SCOPE).AsString();

                // 2. Post the token
                try {
                    postToken(rsAddr, asRes, map);
                } catch (AceException e) {
                    System.out.println(e.getMessage());
                    client4AS.shutdown();
                    System.out.println("Quitting.");
                    return -1;
                }

                OSCOREProfileRequests.setClient(client4RS, ctxDB);

                // 3. Make GET requests to access the resources
                List<String> resources = new ArrayList<>(Arrays.asList(allowedScopes.split(" ")));
                resources.replaceAll(s1 -> s1.substring(s1.indexOf("_") + 1));

                int i = 0;
                while (denialsCount < denials && validTokens.contains(tokenHash)) {
                    boolean isSuccess = getResource(client4RS, rsAddr + "/" + resources.get(i));
                    if (isSuccess && tokenCount == 2) {
                        client4AS.shutdown();
                        if (es != null) {
                            //Shutting down the Executor Service for the Poller
                            es.shutdown();
                        }
                        System.out.println("Test ended successfully.");
                        return 0;
                    }
                    if (!isSuccess) {
                        denialsCount++;
                        if (denialsCount == denials) {
                            System.out.println("Too many denials.");
                            validTokens.remove(tokenHash); // assume the token is not valid anymore
                            break;
                        }
                    }
                    i = (i+1)%resources.size();

                    // wait 'requestInterval' before making another request,
                    // or wake up and ignore the remaining time if the
                    // current tokenhash has been removed from the variable
                    // validToken
                    long curTime = time.getCurrentTime();
                    long deadline = curTime + requestInterval * 1000L;

                    while (time.getCurrentTime() < deadline) {
                        long timeout = deadline - time.getCurrentTime();
                        synchronized (validTokens) {
                            validTokens.wait(timeout);
                            if (!validTokens.contains(tokenHash)) {
                                System.out.println("Learnt that the token was revoked");
                                break;
                            }
                        }
                    }
                }
                System.out.println("Trying to get a new Access Token from the AS...");
                denialsCount = 0;
            }
        }
    }


    public Response getToken(CoapClient client4AS, String aud, String scope) throws AceException, OSException {
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject(aud), CBORObject.FromObject(scope), null);

        Response asRes = OSCOREProfileRequests.getToken(
                client4AS, asUri + "/token", params);

        if (asRes.getCode().isServerError() || asRes.getCode().isClientError()) {
            throw new AceException("Failure response received from the AS: Token not issued");
        }
        return asRes;
    }


    public void postToken(String rsUri, Response asRes, Map<Short, CBORObject> map) throws AceException, OSException {
        // 2. Post the Access Token to the /authz-info endpoint at the RS
        if (map.containsKey(Constants.CNF)) {
            Response rsRes = OSCOREProfileRequests.postToken(
                    rsUri + "/authz-info", asRes, ctxDB, usedRecipientIds);
            System.out.println("\nResponse from RS (token post)");
            System.out.println("Response Code:       " + rsRes.getCode());

            if (rsRes.getCode().isServerError() || rsRes.getCode().isClientError()) {
                throw new AceException("Failure response received from the RS (Posting new token)");
            }
        }
        else {
            CoapResponse rsRes = OSCOREProfileRequests.postTokenUpdate(
                    rsUri + "/authz-info", asRes, ctxDB);
            System.out.println("\nResponse from RS (token update post)");
            System.out.println("Response Code:       " + rsRes.getCode());

            if (rsRes.getCode().isServerError() || rsRes.getCode().isClientError()) {
                throw new AceException("Failure response received from the RS (posting token update)");
            }
        }
    }


    public boolean getResource(CoapClient client, String resourceUri)
            throws ConnectorException, IOException {

        CoapResponse res = doGetRequest(client, resourceUri);
        System.out.println("\nResponse Code:       " + res.getCode() + " - " + res.advanced().getCode().name());

        if (res.getCode().isSuccess()) {
            System.out.println("Response Message:    " + res.getResponseText() + "\n");
        }
        else if (res.getCode().isServerError() || res.getCode().isClientError()) {

            if (res.getOptions().getContentFormat() == Constants.APPLICATION_ACE_CBOR) {
                // print AS Request Creation Hints
                System.out.println("Response Message:    " +
                        AsRequestCreationHints.parseHints(CBORObject.DecodeFromBytes(res.getPayload())) + "\n");
            }
            // increase the counter only if UNAUTHZ is received
            return !res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED);
        }
        return true;
    }


    public CoapResponse doGetRequest(CoapClient client, String resourceUri)
            throws ConnectorException, IOException {

        client.setURI(resourceUri);

        Request request = new Request(CoAP.Code.GET);
        request.getOptions().setOscore(new byte[0]);
        return client.advanced(request);
    }

    // post method. Need to modify the Requester. What do I post, a random value?
//    public CoapResponse doPostRequest(CoapClient client, String resourceUri, String payload)
//            throws ConnectorException, IOException {
//
//        client.setURI(resourceUri);
//
//        Request request = new Request(CoAP.Code.POST);
//        request.getOptions().setOscore(new byte[0]);
//        request.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
//        CBORObject payloadCbor  = CBORObject.FromObject(payload);
//        request.setPayload(payloadCbor.EncodeToBytes());
//        return client.advanced(request);
//    }

    private void parseInputs() throws ParameterException {

        if (scope.size() > 1 || rsUri.size() > 1 || aud.size() > 1) {
            if (scope.size() != rsUri.size() || rsUri.size() != aud.size()) {
                throw new ParameterException(spec.commandLine(),
                        "\nWhen specifying more than one --aud, --scope, or --rsuri, \n" +
                                "the complete list of triplets must be given.\n" +
                                "If one occurrence of --aud, --scope, or --rsuri is found, that value is used \n" +
                                "for the given arguments, and default value is used for the other arguments.\n\n" +
                                "Example: --aud rs1 --scope \"scope1\" \n    is valid.\n" +
                                "The default value for --rsuri will be used.\n\n" +
                                "Example: --aud rs1 --scope \"scope1\" --aud rs2 \n    is NOT valid.\n" +
                                "If two --aud are specified, two --scope and two --rsuri must be specified.\n" +
                                "The first occurrence of each argument composes a triplets.\n");
            }
        }

        // check asUri and prepend the protocol if needed
        asUri = Utils.validateUri(asUri, spec);
        // check rsUri and prepend the protocol if needed
        for (int i = 0; i < rsUri.size(); i++) {
            rsUri.set(i, Utils.validateUri(rsUri.get(i), spec));
        }

        // convert senderId input from hex string to byte array
        sId = Utils.hexStringToByteArray(senderId, spec);

        // convert the OSCORE master secret from string to byte array
        key128 = key.getBytes(Constants.charset);

        // parse revoked tokens notification type
        try {
            isObserve = this.args.notification.observeArgs.observe;
        } catch (NullPointerException e) {
            isObserve = false;
        }
        try {
            isPolling = this.args.notification.pollingArgs.polling;
        } catch (NullPointerException e) {
            isPolling = false;
        }
        try {
            pollingInterval = this.args.notification.pollingArgs.interval;
        } catch (NullPointerException e) {
            pollingInterval = DEFAULT_POLLING_INTERVAL;
        }
        try {
            trlAddr = this.args.trlAddrArg.trlAddress;
        } catch (NullPointerException e) {
            trlAddr = DEFAULT_TRL_ADDR;
        }
    }
}

