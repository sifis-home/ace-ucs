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
package se.sics.ace.coap.oscoreProfile.observe;

import COSE.AlgorithmID;
import COSE.MessageTag;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.*;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import se.sics.ace.*;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.TrlCoapHandler;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.TrlResponses;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.TokenRepository;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;

import static java.lang.Thread.sleep;

/**
 * Resource Server to test with OscoreProtObserveCTestClient
 *
 * @author Marco Rasori
 *
 */
public class OscoreProtObserveRSTestServer {
	
    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {

            // set resource identifier
            super("helloWorld");

            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {

            // respond to the request
            exchange.respond("Hello World!");
        }
    }
    
    /**
     * Definition of the Temp Resource
     */
    public static class TempResource extends CoapResource {

        String tempStr = "19.0 C";
        /**
         * Constructor
         */
        public TempResource() {
            
            // set resource identifier
            super("temp");
            
            // set display name
            getAttributes().setTitle("Temp Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {

            // respond to the request
            exchange.respond(tempStr);
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            exchange.accept();

            tempStr = CBORObject.DecodeFromBytes(exchange.getRequestPayload()).AsString();
            System.out.println(getAttributes().getTitle() + ": temperature changed to "
                    + tempStr + " as requested by client.");
            //exchange.respond(ResponseCode.CREATED);

            exchange.respond(CoAP.ResponseCode.CHANGED,"Temperature successfully changed to " + tempStr);
        }
    }
    
    private static OscoreAuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;

    /**
     * Resource Server CoAP port.
     * The resource server does not use the standard port
     * since the authorization server is using it
     */
    public static int RS_COAP_PORT = 5685;

    /**
     * Symmetric key shared between AS and RS. Used to protect the tokens issued by the AS.
     */
    static byte[] key256Rs = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'K', 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};

    /**
     * Symmetric key shared between AS and RS. Used for the OSCORE security context.
     */
    static byte[] key128rs = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

    private static OSCoreCtxDB ctxDB;

    /**
     * The AS-RS context
     */
    private static OSCoreCtx oscoreCtx;

    private static Timer timer;

    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_helloWorld", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);

        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put("temp", actions3);
        myScopes.put("w_temp", myResource3);
        
        String rsId = "rs1";
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"), myScopes);

        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0,
                AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key256Rs, coseP.getAlg().AsCBOR());

        String tokenFile = TestConfig.testFilePath + "tokens.json";
        String tokenHashesFile = TestConfig.testFilePath + "tokenhashes.json";
        //Delete lingering old files
        File tFile = new File(tokenFile);
        if (!tFile.delete() && tFile.exists()) {
            throw new IOException("Failed to delete " + tFile);
        }
        File thFile = new File(tokenHashesFile);
        if (!thFile.delete() && thFile.exists()) {
            throw new IOException("Failed to delete " + thFile);
        }

        //Set up the inner Authz-Info library
    	ai = new OscoreAuthzInfo(Collections.singletonList("AS"),
                  new KissTime(), null, rsId, valid, ctx,
                  tokenFile, tokenHashesFile, valid, false, 86400000L);

        // process an in-house-built token
        // addTestToken(ctx);

        AsRequestCreationHints archm 
            = new AsRequestCreationHints(
                    "coap://localhost/token", null, false, false);
        Resource hello = new HelloWorldResource();
        Resource temp = new TempResource();
        Resource authzInfo = new CoapAuthzInfo(ai);

        ctxDB = OscoreCtxDbSingleton.getInstance();
      
        rs = new CoapServer();
        rs.add(hello);
        rs.add(temp);
        rs.add(authzInfo);
        rs.addEndpoint(new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(RS_COAP_PORT)
                .setCustomCoapStackArgument(ctxDB)
                .build());

        byte[] senderId = new byte[]{0x11};     // RS identity
        byte[] recipientId = new byte[]{0x33};  // AS identity
        byte[] contextId = new byte[] {0x44};   // RS-AS context ID (hardcoded)
        oscoreCtx = new OSCoreCtx(key128rs, true, null, senderId,
                recipientId, null, null, null, contextId, MAX_UNFRAGMENTED_SIZE);

        String trlAddr = "coap://localhost/trl";
        CoapClient client4AS = OSCOREProfileRequests.buildClient(trlAddr, oscoreCtx, ctxDB);

        // uncomment for observe
        TrlCoapHandler handler = new TrlCoapHandler(TokenRepository.getInstance().getTrlManager());
        CoapObserveRelation relation = OSCOREProfileRequests.
                                          makeObserveRequest(client4AS, trlAddr, handler);

        // uncomment for polling
//        timer = new Timer();
//        timer.schedule(new PollTrl(client4AS, trlAddr), 5000, 5000);


        dpd = new CoapDeliverer(rs.getRoot(), null, archm); 

        rs.setMessageDeliverer(dpd);
        rs.start();
        System.out.println("Server starting");
    }

    /**
     * Stops the server
     * 
     * @throws IOException
     * @throws AceException 
     */
    public static void stop() throws IOException, AceException {
        rs.stop();
        ai.close();
        File tFile = new File(TestConfig.testFilePath + "tokens.json");
        if (!tFile.delete() && tFile.exists()) {
            throw new IOException("Failed to delete " + tFile);
        }
        File thFile = new File(TestConfig.testFilePath + "tokenhashes.json");
        if (!thFile.delete() && thFile.exists()) {
            throw new IOException("Failed to delete " + thFile);
        }
        System.out.println("Server stopped");
    }

    /**
     * Creates a test token locally and process it
     *
     * @throws Exception
     */
    public static void addTestToken(CwtCryptoCtx ctx) throws Exception {
        //Add a test token to authz-info
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("AS"));

        // build oscore CNF claim
        CBORObject osccnf = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();

        byte[] masterSecret = new byte[16];
        new SecureRandom().nextBytes(masterSecret);

        osc.Add(Constants.OS_MS, masterSecret);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));

        osccnf.Add(Constants.OSCORE_Input_Material, osc);

        params.put(Constants.CNF, osccnf);

        AccessToken token = AccessTokenFactory.generateToken(AccessTokenFactory.CWT_TYPE, params);
        CWT cwt = (CWT)token;

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, new byte[]{0x22});
        CBORObject message = CBORObject.FromObject(payload);

        ai.processMessage(new LocalMessage(0, null, null, message));
    }

    public static class PollTrl extends TimerTask {

        CoapClient client = null;
        String srvAddr;

        public PollTrl(CoapClient client, String srvAddr) {
            this.client = client;
            this.srvAddr = srvAddr;
        }

        public void run() {

            CoapResponse response = null;
            try{
                response= OSCOREProfileRequests.makePollRequest(client, srvAddr);
            } catch(AceException e) {
                System.out.println("Exception caught: " + e.getMessage());
                return;
            }

            CBORObject payload;
            try {
                payload = TrlResponses.checkAndGetPayload(response);
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
                trl.updateLocalTrl(CBORObject.DecodeFromBytes(response.getPayload()));
            } catch (AceException e) {
                e.printStackTrace();
            }
        }
    }
}
