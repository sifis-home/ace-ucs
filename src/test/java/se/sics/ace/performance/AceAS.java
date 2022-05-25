/*******************************************************************************
 * Copyright (c) 2019, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.performance;

import COSE.*;
import it.cnr.iit.ucs.properties.components.PipProperties;
import it.cnr.iit.xacml.Category;
import it.cnr.iit.xacml.DataType;
import org.eclipse.californium.core.coap.CoAP;
import se.sics.ace.*;
import se.sics.ace.as.PDP;
import se.sics.ace.as.TrlConfig;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.OscoreAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.performance.peers.Client;
import se.sics.ace.performance.peers.ResourceServer;
import se.sics.ace.ucs.UcsHelper;
import se.sics.ace.ucs.properties.UcsPapProperties;
import se.sics.ace.ucs.properties.UcsPipReaderProperties;

import java.io.*;
import java.util.*;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;

import static java.lang.Thread.sleep;

/**
 * Authorization Server to test with AceClient and AceRS
 *
 * @author Marco Rasori
 *
 */
@CommandLine.Command(name = "a-server",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "Runs the ACE Authorization Server.\n" +
                "The default PDP is the UCS")
public class AceAS implements Callable<Integer> {

    private final static String DEFAULT_CLIENT_SCOPE = "r_temp r_helloWorld";
    private final static String DEFAULT_RESOURCE_SERVER_SCOPE = "r_temp r_helloWorld";
    private final static String DEFAULT_CLIENT_AUD = "rs1";
    private final static String DEFAULT_RESOURCE_SERVER_AUD = "rs1";
    private final static String DEFAULT_CLIENT_SENDER_ID = "0x22";
    private final static String DEFAULT_RESOURCE_SERVER_SENDER_ID = "0x11";
    private final static String DEFAULT_CLIENT_NAME = "ClientA";
    private final static String DEFAULT_RESOURCE_SERVER_NAME = "rs1";
    private final static String DEFAULT_CLIENT_MASTER_SECRET =
            "ClientA-AS-MS---";
    private final static String DEFAULT_RESOURCE_SERVER_MASTER_SECRET =
            "RS1-AS-MS-------"; //16-byte long
    private final static String DEFAULT_RESOURCE_SERVER_TOKEN_PSK =
            "RS1-AS-Default-PSK-for-tokens---"; //32-byte long


    @Option(names = {"-K", "--Kisspdp"},
            required = false,
            description = "Use the KissPDP as PDP.\n" +
                    "(default: UCS)\n")
    private boolean isKissPDP;


    static class Opt {
        @Option(names = {"-n", "--name"},
                required = true,
                defaultValue = "'" + DEFAULT_CLIENT_NAME + "' for the Client;\n" +
                        "          '" + DEFAULT_RESOURCE_SERVER_MASTER_SECRET + "' for the Resource Server",
                description = "The peer name.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String name;
        
        @Option(names = {"-s", "--scope"},
                required = true,
                defaultValue = "'" + DEFAULT_CLIENT_SCOPE + "' for the Client;\n" +
                        "          '" + DEFAULT_RESOURCE_SERVER_SCOPE + "' for the Resource Server",
                description = "The scope.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String scope;
        
        @Option(names = {"-u", "--aud"},
                required = true,
                defaultValue = "'" + DEFAULT_CLIENT_AUD + "' for the Client;\n" +
                        "          '" + DEFAULT_RESOURCE_SERVER_AUD + "' for the Resource Server",
                description = "The audience.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String aud;

        @Option(names = {"-x", "--senderId"},
                required = true,
                defaultValue = "'" + DEFAULT_CLIENT_SENDER_ID + "' for the Client;\n" +
                        "          '" + DEFAULT_RESOURCE_SERVER_SENDER_ID + "' for the Resource Server",
                description = "The Sender ID in HEX used for " +
                        "the OSCORE Security Context with the Authorization Server.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String sId;
        
        @Option(names = {"-m", "--mastersecret"},
                required = true,
                defaultValue = "'" + DEFAULT_CLIENT_MASTER_SECRET + "' for the Client;\n" +
                        "          '" + DEFAULT_RESOURCE_SERVER_SENDER_ID + "' for the Resource Server",
                description = "The symmetric pre-shared key between " +
                        "the Authorization Server and the peer. It is the master " +
                        "secret used for the OSCORE Security Context.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String key;

        @Option(names = {"-k", "--key"},
                required = false,
                defaultValue = DEFAULT_RESOURCE_SERVER_TOKEN_PSK,
                description = "The symmetric pre-shared key between the Resource " +
                        "Server and the Authorization Server. It is used by the " +
                        "Authorization Server to protect the tokens for this " +
                        "Resource Server.\n" +
                        "(default: ${DEFAULT-VALUE})\n")
        String tokenKey;
    }

static class Peer {
    @Option(names = {"-C", "--Client"},
            required = true,
            description = "Add a new Client")
    boolean isClient;

    @Option(names = {"-R", "--Resourceserver"},
            required = true,
            description = "Add a new Resource Server")
    boolean isResourceServer;
}
    static class Args {
        @ArgGroup(exclusive = true, multiplicity = "1")
        Peer peer;

        @ArgGroup(exclusive = false, multiplicity = "0..1")
        Opt opt;
    }

    @ArgGroup(exclusive = false, multiplicity = "0..*")
    List<AceAS.Args> args;

    static OneKey myAsymmKey;

    private static CoapDBConnector db = null;
    private static OscoreAS as = null;
    private static PDP pdp;

    private final static Map<String, String> peerNamesToIdentities = new HashMap<>();
    private final static Map<String, String> peerIdentitiesToNames = new HashMap<>();
    private final static Map<String, String> myIdentities = new HashMap<>();
    private final static byte[] idContext = new byte[] {0x44};

    static String asName = "AS";
    private final String asIdentity = buildOscoreIdentity(new byte[] {0x33}, idContext);

    private static Timer timer;
    

    //--- MAIN
    public static void main(String[] args) {

        int exitCode = new CommandLine(new AceAS()).execute(args);
        if (exitCode != 0) {
            as.stop();
            System.exit(exitCode);
        }
    }



    @Override
    public Integer call() throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        setAttributeValue(TestConfig.testFilePath + "dummy2.txt", "dummy2value");
        setAttributeValue(TestConfig.testFilePath + "dummy_env_attribute.txt", "a");

        setupPDP();

        parseInputs();

        KissTime time = new KissTime();

        TrlConfig trlConfig = new TrlConfig("trl", 3, null, true);

        as = new OscoreAS(asName, db, pdp, time, myAsymmKey,"token", "introspect", trlConfig,
                          CoAP.DEFAULT_COAP_PORT, null, false, (short)1, true,
                          peerNamesToIdentities, peerIdentitiesToNames, myIdentities);
        
        as.start();
        System.out.println("Server starting");
        //as.stop();

        //timer = new Timer();
        //timer.schedule(new AttributeChanger("dummy2.txt", "changedValue"),15000);
        return 0;
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        as.stop();
        pdp.close();
        DBHelper.tearDownDB();
        System.out.println("Server stopped");
    }


    private void parseInputs() throws AceException {

        List<Args> inputClients;
        try {
            inputClients = new ArrayList<>(this.args);
            inputClients.removeIf(c -> c.peer.isResourceServer);
        } catch (NullPointerException e) {
            inputClients = new ArrayList<>();
        }

        List<Args> inputResourceServers;
        try {
            inputResourceServers = new ArrayList<>(this.args);
            inputResourceServers.removeIf(r -> r.peer.isClient);
        } catch (NullPointerException e) {
            inputResourceServers = new ArrayList<>();
        }

        List<Client> clients = new ArrayList<>();
        if (inputClients.isEmpty()) {
            clients.add(new Client(DEFAULT_CLIENT_NAME, DEFAULT_CLIENT_SCOPE,
                    DEFAULT_CLIENT_AUD, DEFAULT_CLIENT_SENDER_ID,
                    DEFAULT_CLIENT_MASTER_SECRET));
        }
        for (Args c : inputClients) {
            clients.add(new Client( c.opt.name, c.opt.scope, c.opt.aud,
                    c.opt.sId, c.opt.key));
        }
        for(Client c : clients) {
            setupClient(c);
        }

        List<ResourceServer> resourceServers = new ArrayList<>();
        if (inputResourceServers.isEmpty()) {
            resourceServers.add(new ResourceServer(DEFAULT_RESOURCE_SERVER_NAME,
                    DEFAULT_RESOURCE_SERVER_SCOPE, DEFAULT_RESOURCE_SERVER_AUD,
                    DEFAULT_RESOURCE_SERVER_SENDER_ID, DEFAULT_RESOURCE_SERVER_MASTER_SECRET,
                    DEFAULT_RESOURCE_SERVER_TOKEN_PSK));
        }
        for (Args r: inputResourceServers) {
            resourceServers.add(new ResourceServer(r.opt.name, r.opt.scope, r.opt.aud,
                    r.opt.sId, r.opt.key, r.opt.tokenKey));
        }
        for (ResourceServer r: resourceServers) {
            setupResourceServer(r);
        }
    }


    private void setupResourceServer(ResourceServer r) throws AceException {

        db.addRS(r.getName(), r.getProfiles(), r.getScopeSet(), r.getAudSet(),
                r.getKeyTypes(), r.getTokenTypes(), r.getCose(), r.getExpiration(),
                r.getSharedPsk(), r.getTokenPsk(), null);
        addIdentity(r.getName(), r.getsId());
        pdp.addIntrospectAccess(r.getName());
    }
    private void setupClient(Client c) throws AceException {

        db.addClient(c.getName(), c.getProfiles(), null, null,
                c.getKeyTypes(), c.getSharedPsk(), null);
        addIdentity(c.getName(), c.getsId());
        pdp.addTokenAccess(c.getName());

        List<String> scopes = new ArrayList<>(Arrays.asList(c.getScope().split(" ")));
        for (String s : scopes) {
            pdp.addAccess(c.getName(), c.getAud(), s);
        }
        //pdp.addAccess("clientA", "rs1", "r_helloWorld", TestConfig.testFilePath + "policy_template_dummy2");
        //pdp.addAccess("clientA", "rs1", "w_temp", TestConfig.testFilePath + "policy_template_dummy2");
    }


    private void addIdentity(String peerName, byte[] peerIdentity) {

        String peerIdentityStr = buildOscoreIdentity(peerIdentity, idContext);
        peerNamesToIdentities.put(peerName, peerIdentityStr);
        peerIdentitiesToNames.put(peerIdentityStr, peerName);
        myIdentities.put(peerName, asIdentity);
    }

    private String buildOscoreIdentity(byte[] senderId, byte[] contextId) {

        if (senderId == null)
            return null;
        String identity = "";

        if (contextId != null) {
            identity += Base64.getEncoder().encodeToString(contextId);
            identity += ":";
        }
        identity += Base64.getEncoder().encodeToString(senderId);

        return identity;

    }


    private void setupPDP() throws AceException {

        if (isKissPDP) {
            pdp = new KissPDP(db);
        }
        else {
            // TODO create the attribute file and fill it with the value? mmh.. we would also
            //      need a policy template that uses that attribute... or we should specify a policy
            //      that uses that attribute.

            UcsPipReaderProperties pipReader = new UcsPipReaderProperties();
            pipReader.addAttribute(
                    "urn:oasis:names:tc:xacml:3.0:environment:dummy_env_attribute",
                    Category.ENVIRONMENT.toString(),
                    DataType.STRING.toString(),
                    TestConfig.testFilePath + "dummy_env_attribute.txt");

            List<PipProperties> pipPropertiesList = new ArrayList<>();
            pipPropertiesList.add(pipReader);

//        pipReader = new UcsPipReaderProperties();
//        pipReader.addAttribute(
//                "urn:oasis:names:tc:xacml:3.0:environment:dummy2",
//                Category.ENVIRONMENT.toString(),
//                DataType.STRING.toString(),
//                TestConfig.testFilePath + "dummy2.txt");
//        pipPropertiesList.add(pipReader);

            UcsPapProperties papProperties =
                    new UcsPapProperties(TestConfig.testFilePath + "policies/");

            pdp = new UcsHelper(db, pipPropertiesList, papProperties);
        }
    }

    public static void setAttributeValue(String fileName, String value) {

        // put in the file "dummy2.txt" the value "dummy2value",
        // which is the value expected from the access policies
        // created from the file "policy_template_dummy2"
        File file = new File(fileName);
        FileWriter fw = null;
        try {
            fw = new FileWriter(file);
            fw.write(value);
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Change the attribute value within the file identified by fileName.
     * This triggers the possible revocation of tokens for the policies
     * that include that attribute.
     */
    public static class AttributeChanger extends TimerTask {

        private final String fileName;
        private final String value;

        public AttributeChanger(String fileName, String value) {
            this.fileName = fileName;
            this.value = value;
        }

        public void run() {
            File file = new File(TestConfig.testFilePath + this.fileName);
            FileWriter fw = null;
            try {
                fw = new FileWriter(file);
                fw.write(this.value);
                fw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
