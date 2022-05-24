package se.sics.ace.performance;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.MessageTag;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.*;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import se.sics.ace.*;
import se.sics.ace.coap.TrlCoapHandler;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.TrlResponses;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.coap.rs.oscoreProfile.OscoreIntrospection;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.TokenRepository;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;

/**
 * Resource Server to test with AceClient and AceAS
 *
 * @author Marco Rasori
 *
 */

// todo (possible improvements):
//  - better way to get the absolute path of Resources class?

@Command(name = "r-server",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "Runs an ACE Resource Server.")
public class AceRS implements Callable<Integer> {

    private final static String DEFAULT_ASURI = "localhost:" + CoAP.DEFAULT_COAP_PORT;
    private final static int DEFAULT_RS_PORT = 5685;

    private final static String DEFAULT_AUD = "rs1";

    private final static String DEFAULT_SCOPE = "r_temp r_helloWorld";
    private final static int DEFAULT_POLLING_INTERVAL = 10;
    private final static int DEFAULT_INTROSPECT_INTERVAL = 10;

    private final static String DEFAULT_TRL_ADDR = "/trl";
    private final static String DEFAULT_SENDER_ID = "0x11";
    private final static String DEFAULT_TOKEN_PSK = "RS1-AS-Default-PSK-for-tokens---"; //32-byte long
    private final static String DEFAULT_MASTER_SECRET = "RS1-AS-MS-------"; //16-byte long


    @Spec
    CommandSpec spec;

    @Option(names = {"-a", "--asuri"},
            required = false,
            defaultValue = DEFAULT_ASURI,
            description = "The URI of the Authorization Server.\n" +
                    "Hostname and port MUST be specified.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String asUri;

    @Option(names = {"-l", "--listeningport"},
            required = false,
            defaultValue = "" + DEFAULT_RS_PORT,
            description = "The port on which the Resource Server is listening.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String rsPort;

    @Option(names = {"-u", "--aud"},
            required = false,
            defaultValue = DEFAULT_AUD,
            description = "The audience of this Resource Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String aud;

    @Option(names = {"-s", "--scope"},
            required = false,
            defaultValue = DEFAULT_SCOPE,
            description = "The scope accepted by this Resource Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String scope;

    @Option(names = {"-m", "--mastersecret"},
            required = false,
            defaultValue = "" + DEFAULT_MASTER_SECRET,
            description = "The symmetric pre-shared key between the Resource " +
                    "Server and the Authorization Server. It is the master " +
                    "secret used for the OSCORE Security Context.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String key;

    @Option(names = {"-x", "--senderid"},
            required = false,
            defaultValue = "" + DEFAULT_SENDER_ID,
            description = "The Sender ID in HEX used for " +
                    "the OSCORE Security Context with the Authorization Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String senderId;

    @Option(names = {"-k", "--key"},
            required = false,
            defaultValue = "" + DEFAULT_TOKEN_PSK,
            description = "The symmetric pre-shared key between the Resource " +
                    "Server and the Authorization Server. It is used by the " +
                    "Authorization Server to protect the tokens for this " +
                    "Resource Server.\n" +
                    "(default: ${DEFAULT-VALUE})\n")
    private String tokenKey;

    static class IntrospectionArgs {
        @Option(names = {"-i", "--introspection"},
                required = true,
                description = "The Resource Server introspects the trl endpoint at the AS.\n")
        boolean introspect;

        @Option(names = {"-y", "--introspectioninterval"},
                required = false,
                defaultValue = "" + DEFAULT_INTROSPECT_INTERVAL,
                description = "The time interval (in seconds) between two introspection " +
                        "requests to the introspection endpoint.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        int interval;
    }

    static class PollingArgs {
        @Option(names = {"-p", "--polling"},
                required = true,
                description = "The Resource Server polls the trl endpoint at the AS.\n")
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
                description = "The Resource Server observes the trl endpoint at the AS.\n")
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
        @ArgGroup(exclusive = false, multiplicity = "1")
        AceRS.PollingArgs pollingArgs;
        @ArgGroup(exclusive = false, multiplicity = "1")
        AceRS.ObserveArgs observeArgs;
    }

    static class TrlArgs {
        @ArgGroup(exclusive = true, multiplicity = "1")
        AceRS.NotificationArgs notification;
        @ArgGroup(exclusive = false)
        AceRS.TrlAddrArg trlAddrArg;
    }

    static class Args {
        @ArgGroup(exclusive = false, multiplicity = "1")
        AceRS.TrlArgs trlArgs;
        @ArgGroup(exclusive = false, multiplicity = "1")
        AceRS.IntrospectionArgs IntrospectionArgs;
    }

    @ArgGroup(exclusive = true)
    AceRS.Args args;

    private static OscoreAuthzInfo ai = null;
    private static CoapServer rs = null;

    // Symmetric key shared between AS and RS. Used to protect the tokens issued by the AS.
    private static byte[] key256Rs;

    private static CwtCryptoCtx cwtCryptoCtx;
    private static byte[] key128;

    private static OSCoreCtx ctx;
    private static OSCoreCtxDB ctxDB;

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    static String tokenFile = TestConfig.testFilePath + "tokens.json";
    static String tokenHashesFile = TestConfig.testFilePath + "tokenhashes.json";

    static String asName = "AS";
    private static int rsCoapPort;

    static Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
    private static OscoreIntrospection introspection = null;

    private static final byte[] idContext = new byte[] {0x44};
    private byte[] sId;

    private boolean isPolling = false;
    private boolean isObserve = false;

    private boolean isIntrospect = false;

    private int pollingInterval;

    private int introspectInterval;

    private String trlAddr;

    private final List<String> syncCtisList = new ArrayList<>();

    private final Map<String, ScheduledExecutorService> introspectorMap = new HashMap<>();


    //--- MAIN
    public static void main(String[] args) {

        int exitCode = new CommandLine(new AceRS()).execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }



    @Override
    public Integer call() throws Exception {

        parseInputs();

        parseScope(scope);
        setUpCwtCryptoCtx();
        setUpServer();

        rs.start();
        System.out.println("Server starting");

        if (isObserve) {
            CoapClient client4AS = OSCOREProfileRequests.buildClient(asUri, ctx, ctxDB);
            // 1. Make Observe request to the /trl endpoint
            TrlCoapHandler handler = new TrlCoapHandler(
                    TokenRepository.getInstance().getTrlManager());
            CoapObserveRelation relation = OSCOREProfileRequests.
                    makeObserveRequest(client4AS, asUri + trlAddr, handler);
        }

        if (isPolling) {
            CoapClient client4AS = OSCOREProfileRequests.buildClient(asUri, ctx, ctxDB);
            // 1. Make poll request to the /trl endpoint
            ScheduledExecutorService executorService = Executors
                    .newSingleThreadScheduledExecutor();
            executorService.scheduleAtFixedRate(
                    new Poller(client4AS, asUri + trlAddr),
                        pollingInterval, pollingInterval, TimeUnit.SECONDS);
        }

        Set<String> validTokens = TokenRepository.getInstance().getCtis();
        for (String cti : validTokens) {
            startIntrospector(cti);
        }

        while(isIntrospect) {
            synchronized (syncCtisList) {
                while (syncCtisList.isEmpty()) {
                    syncCtisList.wait();
                }
                ListIterator<String> iter = syncCtisList.listIterator();
                while(iter.hasNext()) {
                    startIntrospector(iter.next());
                    iter.remove();
                }
                syncCtisList.notifyAll();
            }
        }

        return 0;
    }

    private void startIntrospector(String cti) {
        ScheduledExecutorService executorService = Executors
                .newSingleThreadScheduledExecutor();
        executorService.scheduleAtFixedRate(
                new Introspector(cti),
                introspectInterval, introspectInterval, TimeUnit.SECONDS);
        introspectorMap.put(cti, executorService);
    }

    class Introspector implements Runnable {

        String cti;

        public Introspector(String cti) {
            this.cti = cti;
        }

        @Override
        public void run() {
            //System.out.println("New Introspect thread (" +
            //        Thread.currentThread().getName() + ") for token " + cti);
            try {
                CBORObject cticb = CBORObject.FromObject(Base64.getDecoder().decode(cti));
                Map<Short, CBORObject> map = introspection.getParams(cticb.GetByteString());

                CBORObject active = map.get(Constants.ACTIVE);
                if (active != null && active.isFalse()) {
                    System.out.println("Introspection result: Token is not valid.");
                    TokenRepository.getInstance().removeToken(cti);
                    System.out.println("Access Token removed.");

                    introspectorMap.get(cti).shutdown();
                    introspectorMap.remove(cti);
                }
                else {
                    System.out.println("Introspection result: Token is valid.");
                }
            } catch (AceException | IntrospectionException e) {
                e.printStackTrace();
            }

        }
    }


    class Poller implements Runnable {

        CoapClient client4AS;
        String trlUri;

        public Poller(CoapClient client4AS, String trlUri) {
            this.client4AS = client4AS;
            this.trlUri = trlUri;
        }

        @Override
        public void run() {
            CoapResponse responseTrl = null;
            try {
                System.out.println("Now polling:" + new Timestamp(System.currentTimeMillis()));
                responseTrl = OSCOREProfileRequests.makePollRequest(client4AS, trlUri);
            } catch (AceException e) {
                e.printStackTrace();
            }

            CBORObject payload;
            try {
                payload = TrlResponses.checkAndGetPayload(responseTrl);
                if (payload.getType() == CBORType.Map &&
                        Constants.getParams(payload).containsKey(Constants.TRL_ERROR)) {
                    System.out.println("Trl response contains an error");
                    return;
                }
            } catch (AceException e) {
                e.printStackTrace();
            }

            TokenRepository.TrlManager trl = TokenRepository.getInstance().getTrlManager();
            try {
                trl.updateLocalTrl(CBORObject.DecodeFromBytes(responseTrl.getPayload()));
            } catch (AceException e) {
                e.printStackTrace();
            }
        }
    }


    private void setUpServer()
            throws AceException, IOException, CoseException, OSException,
            ClassNotFoundException, InstantiationException, IllegalAccessException {

        KissValidator valid = new KissValidator(Collections.singleton(aud), myScopes);
        deleteOldTokenFiles();

        ctxDB = OscoreCtxDbSingleton.getInstance();

        ctx = new OSCoreCtx(key128, true, null,
                sId, // RS identity
                new byte[]{0x33},  // AS identity
                null, null, null, idContext, MAX_UNFRAGMENTED_SIZE);
        if (isIntrospect) {
            introspection =
                    new OscoreIntrospection(ctx, asUri + "/introspect", ctxDB);
        }

        //Set up the inner Authz-Info library
        ai = new OscoreAuthzInfo(Collections.singletonList(asName),
                new KissTime(), introspection, aud, valid, cwtCryptoCtx,
                tokenFile, tokenHashesFile, valid, false, 86400000L, syncCtisList);

        rs = new CoapServer();

        List<String> resources = getClassResourcesNames(scope);
        for (String res : resources) {
            rs.add((Resource) Class.forName(res).newInstance());
        }

        rs.add(new CoapAuthzInfo(ai));

        rs.addEndpoint(new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(rsCoapPort)
                .setCustomCoapStackArgument(ctxDB)
                .build());

        AsRequestCreationHints archm = new AsRequestCreationHints(
                asUri, null, false, false); //todo should include /token?
        CoapDeliverer dpd = new CoapDeliverer(rs.getRoot(), null, archm);
        rs.setMessageDeliverer(dpd);
    }

    /**
     * Stops the server
     * 
     * @throws IOException
     * @throws AceException 
     */
    public void stop() throws IOException, AceException {
        rs.stop();
        ai.close();
        deleteOldTokenFiles();
        System.out.println("Server stopped");
    }


    private void deleteOldTokenFiles() throws IOException {
        //Delete lingering old files
        File tFile = new File(tokenFile);
        if (!tFile.delete() && tFile.exists()) {
            throw new IOException("Failed to delete " + tFile);
        }
        File thFile = new File(tokenHashesFile);
        if (!thFile.delete() && thFile.exists()) {
            throw new IOException("Failed to delete " + thFile);
        }
    }


    private void setUpCwtCryptoCtx() {
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0,
                AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);

        cwtCryptoCtx = CwtCryptoCtx.encrypt0(key256Rs, coseP.getAlg().AsCBOR());
    }


    private List<String> getClassResourcesNames(String scope) {
        List<String> resources = new ArrayList<>(Arrays.asList(this.scope.split(" ")));
        resources.replaceAll(s -> s.substring(s.indexOf("_") + 1));
        resources.replaceAll(s -> s.substring(0, 1).toUpperCase() + s.substring(1));
        resources.replaceAll(s -> "se.sics.ace.performance.resources." + s + "Resource");
        return resources;
    }


    private void parseScope(String scope) throws AceException {

        List<String> scopes = new ArrayList<>(Arrays.asList(scope.split(" ")));

        for (String s : scopes) {
            if (s.chars().filter(ch -> ch == '_').count() != 1) {
                throw new AceException("Not supported scope: " + s);
            }
            Set<Short> actions = new HashSet<>();
            if (s.startsWith("r_") || s.startsWith("rw_") || s.startsWith("wr_")) {
                actions.add(Constants.GET);
            }
            if (s.startsWith("w_") || s.startsWith("rw_") || s.startsWith("wr_")) {
                actions.add(Constants.POST);
            }

            Map<String, Set<Short>> myResource = new HashMap<>();
            myResource.put(s.substring(s.indexOf("_") + 1), actions);
            myScopes.put(s, myResource);
        }
    }


    private void parseInputs() throws ParameterException {

        // check asUri and prepend the protocol if needed
        asUri = validateUri(asUri);

        // check that rs port number is in range
        rsCoapPort = validatePort(rsPort);

        // convert senderId input from hex string to byte array
        sId = hexStringToByteArray(senderId);

        // convert the OSCORE master secret from string to byte array
        key128 = key.getBytes(Constants.charset);

        // convert the PSK for tokens from string to byte array
        key256Rs = tokenKey.getBytes(Constants.charset);

        // parse revoked tokens notification type
        try {
            isObserve = this.args.trlArgs.notification.observeArgs.observe;
        } catch (NullPointerException e) {
            isObserve = false;
        }
        try {
            isPolling = this.args.trlArgs.notification.pollingArgs.polling;
        } catch (NullPointerException e) {
            isPolling = false;
        }
        try {
            pollingInterval = this.args.trlArgs.notification.pollingArgs.interval;
        } catch (NullPointerException e) {
            pollingInterval = DEFAULT_POLLING_INTERVAL;
        }
        try {
            trlAddr = this.args.trlArgs.trlAddrArg.trlAddress;
        } catch (NullPointerException e) {
            trlAddr = DEFAULT_TRL_ADDR;
        }
        try {
            isIntrospect = this.args.IntrospectionArgs.introspect;
        } catch (NullPointerException e) {
            isIntrospect = false;
        }
        try {
            introspectInterval = this.args.IntrospectionArgs.interval;
        } catch (NullPointerException e) {
            introspectInterval = DEFAULT_INTROSPECT_INTERVAL;
        }
    }


    private String validateUri(String srvUri) throws ParameterException {
        try {
            if (!srvUri.contains("://")) {
                srvUri = "coap://" + srvUri;
            }
            URI uri = new URI(srvUri);
            if (uri.getHost() == null || uri.getPort() == -1) {
                throw new URISyntaxException(uri.toString(),
                        "URI must have host and port parts");
            }
            return uri.toString();
        } catch (URISyntaxException ex) {
            // validation failed
            throw new ParameterException(spec.commandLine(),
                    String.format("Server address not valid:\n > '%s'\n", srvUri));
        }
    }


    private int validatePort(String portStr) throws ParameterException {
        int port = Integer.parseInt(portStr);
        if (port < 1 || port > 65535) {
            throw new ParameterException(spec.commandLine(),
                    String.format("Port number not valid:\n > '%s'\n", port));
        }
        return port;
    }


    private byte[] hexStringToByteArray(String str) throws ParameterException {
        String s = str.replace("0x", "");
        try {
            Integer.parseInt(s, 16);
        }
        catch(NumberFormatException nfe)
        {
            throw new ParameterException(spec.commandLine(),
                    String.format("Hexadecimal value is not valid:\n > '%s'", str));
        }

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
