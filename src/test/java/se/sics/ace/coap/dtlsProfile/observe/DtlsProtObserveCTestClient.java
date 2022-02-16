package se.sics.ace.coap.dtlsProfile.observe;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.junit.Assert;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.lang.Thread.sleep;
/*
        C                                RS                   AS
        | [---- Resource Request ------>]|                     |
        |                                |                     |
        | [<-AS Request Creation Hints-] |                     |
        |                                |                     |
        | ------- Token Request ---------------------------->  |
        |                                |                     |
        | <---------------------------- Access Token --------- |
        |                                 + Access Information |


                     Retrieving an Access Token
 */
/*
        C                                RS                   AS
        | [------- Access Token ------>] |                     |
        |                                |                     |
        | <==== DTLS channel setup ====> |                     |
        |                                |                     |
        | ==== Authorized Request =====> |                     |
        |                                |                     |
        | <===== Protected Resource ==== |                     |

                        Protocol overview
 */

/**
 * This test verifies that a token can be used to retrieve different protected resources
 * Also, it tests the interaction between the client and both the servers.
 * The mode (PSK or RPK) can be specified as input of the Main method:
 * -psku:   (psk unprotected). In C2RS communication, post the token to authz-info and then request
 * -psk:    In C2RS communication, connect to the server, passing the token through psk-identity
 * -rpk:    In C2RS communication, post the token to authz-info and then request
 *
 * Finally, it tests the notification mechanism through a request to the trl endpoint.
 * The client sends an Observe request, and the AS replies with the list of revoked
 * tokens for this client.
 * Each time a token pertaining to this client is inserted or removed from the trl (token
 * revocation list), the AS sends to the client the list of tokens in the trl that pertain
 * to this client.
 *
 * Procedure:
 * 1) Run the DtlsProtObserveASTestServer.java
 * 2) Run the DtlsProtObserveRSTestServer.java
 * 3) Run the DtlsProtObserveCTestServer.java
 *
 *  Test explained:
 *  First, the Client "clientA" makes a request to the AS to observe the trl.
 *  Then, clientA makes a token request to AS. It asks for the scope "r_temp w_temp r_helloWorld foobar" (that
 *  identifies the resources "r_temp", "w_temp", "r_helloWorld",and "foobar") at the RS "rs1".
 *  AS generates a token for the allowed resources, i.e., "r_temp", "w_temp", and "r_helloWorld", and sends the scope
 *  "r_temp w_temp r_helloWorld" to the client together with other claims.
 *
 *  In PSK unprotected mode, the client posts the access token on an unprotected channel. Then, it uses the key
 *  identifier (COSE kid) as psk-identity in the DTLS handshake with the RS.
 *  In PSK mode, the client uses the access token as psk-identity in the DTLS handshake with the RS.
 *  In RPK mode, the client extracts the RS public key from the RS_CNF claim and uses it in the DTLS handshake with
 *  the RS.
 *  The client sets the URI specifying the resource (e.g., "coap://localhost:" + RS_COAP_SECURE_PORT + "/temp")
 *  and makes the request.
 *  The request might be either a GET, to obtain the reading of a protected resource, or a POST, to modify the value of
 *  the protected resource.
 *  This test loops, making three GET requests and then one POST request. Each request happens after three seconds form
 *  the previous request.
 *
 *  Note that, since we are making the test on the localhost, AS and RS CoAP ports must be different.
 *  RS secure port is set to 5685, while AS uses the default secure port (5684).
 *
 * @author Marco Rasori
 */

public class DtlsProtObserveCTestClient {

    /**
     * Client identifier, used with the authorization server during a token request in PSK mode
     */
    public static String clientId = "clientA";

    /**
     * Symmetric key shared with the authorization server
     */
    static byte[] key128 = {'C', '-', 'A', 'S', ' ', 'P', 'S', 'K', 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * Client asymmetric key, used in RPK mode
     */
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";

    /**
     * Resource Server CoAP secure port.
     * The resource server does not use the standard port
     * since the authorization server is using it
     */
    public static int RS_COAP_SECURE_PORT = 5686;


    public DtlsProtObserveCTestClient(String id, byte[] key128, Integer port){

        DtlsProtObserveCTestClient.clientId = id;
        if (key128 != null)
            DtlsProtObserveCTestClient.key128 = key128;
        if (port != null)
            DtlsProtObserveCTestClient.RS_COAP_SECURE_PORT = port;
    }

    public static void main(String[] args) throws Exception {

        // default configuration if no args are passed: PSK with unprotected request at authz-info endpoint
        boolean unprotectedRequest = true;
        boolean pskProfile = true;

        OneKey clientAsymKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));

        // parse input
        if (args.length > 0) {
            int index = 0;
            while (index < args.length) {
                String arg = args[index];
                if ("-psk".equals(arg)) {
                    pskProfile = true;
                    unprotectedRequest = false;
                    index++;
                } else if ("-psku".equals(arg)) {
                    pskProfile = true;
                    unprotectedRequest = true;
                    index++;
                } else if ("-rpk".equals(arg)) {
                    pskProfile = false;
                    index++;
                }
            }
        }

        OneKey psk = null;
        if (pskProfile) {
            psk = initPsk();
        }

        System.out.println("\n--------STARTING COMMUNICATION WITH AS--------\n");

        InetSocketAddress asAddress =
                new InetSocketAddress("localhost", CoAP.DEFAULT_COAP_SECURE_PORT);

        // 1. Make Observe request to the /trl endpoint
        CoapObserveRelation relation;
        if (pskProfile) {
            relation = DTLSProfileRequests.makeObserveRequest(
                    asAddress, "trl", psk);
        }
        else {
            relation = DTLSProfileRequests.makeObserveRequest(
                    asAddress, "trl", clientAsymKey);
        }

        // 2. Make Access Token request to the /token endpoint
        // fill params
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp w_temp r_helloWorld foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));

        CoapResponse responseAs;
        if (pskProfile) {
            responseAs = DTLSProfileRequests.getToken(asAddress, "token",
                    Constants.getCBOR(params), psk);
        }
        else {
            OneKey clientPublicKey = clientAsymKey.PublicKey();
            CBORObject reqCnf = CBORObject.NewMap();
            reqCnf.Add(Constants.COSE_KEY_CBOR, clientPublicKey.AsCBOR());
            params.put(Constants.REQ_CNF, reqCnf);

            responseAs = DTLSProfileRequests.getToken(asAddress, "token",
                    Constants.getCBOR(params), clientAsymKey);
        }

        System.out.println("\n---------COMMUNICATION WITH AS ENDED----------\n");

        CBORObject resAs = CBORObject.DecodeFromBytes(responseAs.getPayload());
        Map<Short, CBORObject> mapAs = Constants.getParams(resAs);

        // print response code and the retrieved claims
        System.out.println("Response Code:   " + responseAs.getCode() + " - " + responseAs.advanced().getCode().name());
        System.out.println("Payload content: " + mapAs);

        // extract the access token to be sent to the RS
        CBORObject token = mapAs.get(Constants.ACCESS_TOKEN);
        CBORObject tokenAsCbor = CBORObject.DecodeFromBytes(token.GetByteString());


        System.out.println("\n------STARTING COMMUNICATION WITH RS (1)----\n");

        // 3. Post the Access Token to the /authz-info endpoint at the RS
        CoapClient c2rs;
        if (pskProfile) {
            // use the COSE key contained in the CNF claim to build the PoP key to use with the RS
            CBORObject coseKey = mapAs.get(Constants.CNF).get(Constants.COSE_KEY);
            OneKey popKey = new OneKey(coseKey);

            if (unprotectedRequest) { // PSK, POST the access token to authz-info and then request
                // POST the access token through an unprotected channel
                CoapResponse responseRs = DTLSProfileRequests.postToken("coap://localhost/authz-info", tokenAsCbor, null);
                CBORObject resRs = CBORObject.DecodeFromBytes(responseRs.getPayload());

                // if the token was processed successfully by the RS,
                // the payload of its response contains the claims CTI and SUB
                // print the response code and the claims in the payload
                System.out.println("Response Code:   " + responseRs.getCode() + " - " + responseRs.advanced().getCode().name());
                System.out.println("Payload content: [CTI]   " + resRs.get(CBORObject.FromObject(Constants.CTI)));
                System.out.println("                 [SUB]   " + resRs.get(CBORObject.FromObject(Constants.SUB)));

                // prepare the CoAP client to establish a DTLS channel.
                // extracting KID, used to build the psk-identity for the DTLS handshake
                byte[] kidB = coseKey.get(Constants.KID).GetByteString();
                c2rs = DTLSProfileRequests.getPskClient(
                        new InetSocketAddress("localhost", RS_COAP_SECURE_PORT),
                        kidB, popKey);
            } else { // PSK (use the access token as psk-identity)
                // prepare the CoAP client to establish a DTLS channel.
                // the access token is used as psk-identity in the DTLS handshake
                c2rs = DTLSProfileRequests.getPskClient(
                        new InetSocketAddress("localhost", RS_COAP_SECURE_PORT),
                        tokenAsCbor, popKey);
            }
        } else { // RPK (C -> RS)
            CoapResponse responseRs = DTLSProfileRequests.postToken("coap://localhost/authz-info", tokenAsCbor, null);
            CBORObject cbor = CBORObject.FromObject(responseRs.getPayload());
            Assert.assertEquals("CREATED", responseRs.getCode().name());
            Assert.assertNotNull(cbor);

            // get RS public key from RS_CNF claim
            CBORObject coseKey = mapAs.get(Constants.RS_CNF).get(Constants.COSE_KEY);
            OneKey rsAsymKey = new OneKey(coseKey);

            c2rs = DTLSProfileRequests.getRpkClient(clientAsymKey, rsAsymKey);
        }

        System.out.println("\n--------COMMUNICATION WITH RS ENDED (1)------\n");

//        doGetRequest(c2rs, "temp");
//        doPostRequest(c2rs, "temp", "22.0 C");
//        doGetRequest(c2rs, "helloWorld");

        // 4. Make GET and POST requests to access the resources
        int count = 0;
        int randomTemp;
        CoapResponse res;
        while(true) {
            if (count%4 != 0) {
                res = doGetRequest(c2rs, "temp");
            }
            else {
                randomTemp = (int)(Math.random()*100);
                res = doPostRequest(c2rs, "temp", randomTemp + ".0 C");
            }
            // print response code and the message from the RS
            System.out.println("\nResponse Code:       " + res.getCode() + " - " + res.advanced().getCode().name());
            System.out.println(  "Response Message  :  " + res.getResponseText() + "\n");

//            if (!CoAP.ResponseCode.isSuccess(res.advanced().getCode())){
//                System.out.println("Received an error code. Terminating.");
//                return;
//            }
            count++;
            sleep(3000);
        }

    }


    public static CoapResponse doGetRequest(CoapClient client, String resource) throws Exception {

        client.setURI("coaps://localhost:" + RS_COAP_SECURE_PORT + "/" + resource);
        return client.get();
    }


    public static CoapResponse doPostRequest(CoapClient client, String resource, String payload) throws Exception {

        client.setURI("coaps://localhost:" + RS_COAP_SECURE_PORT + "/" + resource);
        CBORObject payloadCbor = CBORObject.FromObject(payload);
        return client.post(payloadCbor.EncodeToBytes(), Constants.APPLICATION_ACE_CBOR);
    }

    public static OneKey initPsk() throws CoseException {

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        byte[] kid = clientId.getBytes(StandardCharsets.UTF_8);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        return new OneKey(keyData);
    }
}

