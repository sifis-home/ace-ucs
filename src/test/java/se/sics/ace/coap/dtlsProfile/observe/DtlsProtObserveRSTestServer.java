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
package se.sics.ace.coap.dtlsProfile.observe;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.dtlsProfile.DtlspPskStore;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Resource Server to test with DtlsProtObserveCTestClient
 *
 * @author Marco Rasori
 */
public class DtlsProtObserveRSTestServer {


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

            exchange.respond("Temperature successfully changed to " + tempStr);
        }

    }

    private static AuthzInfo ai = null;

    private static CoapServer rs = null;

    private static CoapDeliverer dpd = null;

    /*
     * Resource Server CoAP secure port.
     * The resource server does not use the standard port
     * since the authorization server is using it
     */
    public static final int RS_COAP_SECURE_PORT = 5686;

    /**
     * RS Asymmetric key (ECDSA_256)
     */
    private static String rpk = "piJYILr/9Frrqur4bAz152+6hfzIG6v/dHMG+SK7XaC2JcEvI1ghAKryvKM6og3sNzRQk/nNqzeAfZsIGAYisZbRsPCE3s5BAyYBAiFYIIrXSWPfcBGeHZvB0La2Z0/nCciMirhJb8fv8HcOCyJzIAE=";

    public static String rsId = "rs1";

    /**
     * Symmetric key for the pre-shared authentication key shared with the AS
     */
    static byte[] key128Rs = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'A', 'u', 't', 'h', 'K', 14, 15, 16};

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


        KissValidator valid = new KissValidator(Collections.singleton(rsId), myScopes);

        //Symmetric key shared with the AS. The AS can protect the tokens with this key.
        byte[] key256Rs = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'K', 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

        byte[] keyDerivationKey = {'f', 'f', 'f', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        int derivedKeySize = 16;

        // RS asymmetric key (used in RPK mode)
        OneKey asymmetric = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rpk)));

        // Set up COSE parameters using the psk (key256) shared with the AS.
        // In PSK mode, this secret information will be used to decrypt the token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key256Rs, coseP.getAlg().AsCBOR());

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
        ai = new AuthzInfo(Collections.singletonList("AS"),
                new KissTime(), null, rsId, valid, ctx, keyDerivationKey, derivedKeySize,
                tokenFile, tokenHashesFile, valid, false, 86400000L);

        // process an in-house-built token
        addTestToken(ctx);

        AsRequestCreationHints archm
                = new AsRequestCreationHints(
                "coaps://blah/authz-info/", null, false, false);
        Resource hello = new HelloWorldResource();
        Resource temp = new TempResource();
        Resource authzInfo = new CoapAuthzInfo(ai);

        rs = new CoapServer();
        rs.add(hello);
        rs.add(temp);
        rs.add(authzInfo);

        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));

        DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(dtlsConfig)
                .setAddress(
                        new InetSocketAddress(RS_COAP_SECURE_PORT));

        DtlspPskStore psk = new DtlspPskStore(ai);
        config.setAdvancedPskStore(psk);
        config.setCertificateIdentityProvider(
                new SingleCertificateProvider(asymmetric.AsPrivateKey(), asymmetric.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(new X509Certificate[0],
                new RawPublicKeyIdentity[0], certTypes);
        config.setAdvancedCertificateVerifier(verifier);

        DTLSConnector connector = new DTLSConnector(config.build());
        CoapEndpoint cep = new CoapEndpoint.Builder().setConnector(connector)
                .setConfiguration(Configuration.getStandard()).build();
        rs.addEndpoint(cep);
        //Add a CoAP (no 's') endpoint for authz-info
        CoapEndpoint aiep = new CoapEndpoint.Builder().setInetSocketAddress(
                new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
        rs.addEndpoint(aiep);

        dpd = new CoapDeliverer(rs.getRoot(), null, archm, cep);

        InetSocketAddress asAddress =
                new InetSocketAddress("localhost", CoAP.DEFAULT_COAP_SECURE_PORT);
        OneKey pskKey = initPsk();
        CoapClient client4AS = DTLSProfileRequests.buildClient(asAddress, "trl", pskKey);

        // uncomment for observe
//        TrlCoapHandler handler = new TrlCoapHandler();
//        CoapObserveRelation relation =
//                DTLSProfileRequests.makeObserveRequest(client4AS, handler);

        // uncomment for polling
        timer = new Timer();
        timer.schedule(new PollTrl(client4AS), 5000, 5000);

        rs.setMessageDeliverer(dpd);
        rs.start();
        System.out.println("Server starting");
        //stop();

// observe:
//        CBORObject keyData = CBORObject.NewMap();
//        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
//        byte[] kid = rsId.getBytes(StandardCharsets.UTF_8);
//        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
//        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128Rs));
//        OneKey pskRsAs = new OneKey(keyData);
//
//        CoapObserveRelation relation;
//        if (pskProfile) {
//            relation = DTLSProfileRequests.makeObserveRequest(
//                    "coaps://localhost/trl", pskRsAs);
//        }
//        else {
//            relation = DTLSProfileRequests.makeObserveRequest(
//                    "coaps://localhost/trl", asymmetric);
//        }
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
        byte[] key128 = {'k', 'e', 'y', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject(rsId));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("AS"));

        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);

        byte[] kid = new byte[]{0x01, 0x02, 0x03};
        CBORObject kidC = CBORObject.FromObject(kid);
        key.add(KeyKeys.KeyId, kidC);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        ai.processMessage(new LocalMessage(0, null, null, token.encode(ctx)));
    }

    public static OneKey initPsk() throws CoseException {

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        byte[] kid = rsId.getBytes(StandardCharsets.UTF_8);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128Rs));
        return new OneKey(keyData);
    }

    public static class PollTrl extends TimerTask {

        CoapClient client = null;

        public PollTrl(CoapClient client) {
            this.client = client;
        }

        public void run() {

            CoapResponse response = null;
            try {
                response = DTLSProfileRequests.makePollRequest(client);
            } catch (AceException e) {
                System.out.println("Exception caught: " + e.getMessage());
            }

            TokenRepository.TrlManager trl = TokenRepository.getInstance().getTrlManager();
            try {
                trl.updateLocalTrl(CBORObject.DecodeFromBytes(response.getPayload()));
            } catch (AceException e) {
                e.printStackTrace();
            }
            prettyPrintReceivedTokenHashes(CBORObject.DecodeFromBytes(response.getPayload()));
        }

        private void prettyPrintReceivedTokenHashes(CBORObject payload) {
            List<String> hashes = new ArrayList<>();
            for (int i = 0; i < payload.size(); i++) {
                byte[] tokenHashB = payload.get(i).GetByteString();
                String tokenHashS = new String(tokenHashB, Constants.charset);
                hashes.add(tokenHashS);
            }
            System.out.println("List of received token hashes: " + hashes);
        }
    }
}
