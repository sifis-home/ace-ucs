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
package se.sics.ace.oscore.group;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.junit.Assert;
import com.upokecenter.cbor.CBORObject;
import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSException;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

/**
 * FIXME: Needs updating after import of master code
 * 
 * An application for the OSCORE profile interactions between client and server.
 * Using the OSCORE ACE profile.
 * 
 * Posts a token to the GM and then proceeds to send a join request followed by
 * printing the received join response.
 * 
 * Use this client with the server TestOscorepRSGroupOSCORE
 * 
 * If a Group OSCORE context should be derived that can be done by using code
 * from the JUnit test testSuccessGroupOSCOREMultipleRolesContextDerivation in
 * TestOscorepClient2RSGroupOSCORE.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Hoeglund
 *
 */
public class OscorepClient2RSGroupOSCORE {

    // Private and public key to be used in the OSCORE group by the joining client (EDDSA)
    private static String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

    // Set EDDSA with curve Ed25519 for countersignatures
    private static int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();

    /**
     * The cnf key used in these tests
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    public static void main(String[] args) {
        try {
            performJoinOSCOREProfile();
        } catch (IllegalStateException | InvalidCipherTextException | CoseException | AceException | OSException
                | ConnectorException | IOException e) {
            System.err.print("Join procedure failed: ");
            e.printStackTrace();
        }
    }

    // M.T. & Rikard
    /**
	 * Post to Authz-Info, then perform join request using multiple roles. Uses
	 * the ACE OSCORE Profile.
	 * 
	 * @throws AceException if ACE processing fails
	 * @throws CoseException if COSE processing fails
	 * @throws InvalidCipherTextException if cipher processing fails
	 * @throws IllegalStateException on illegal state
	 * @throws OSException if OSCORE processing fails
	 * @throws IOException on input/output error
	 * @throws ConnectorException if connection has an issue
	 */
    public static void performJoinOSCOREProfile() throws IllegalStateException, InvalidCipherTextException, CoseException, AceException, OSException, ConnectorException, IOException {

        /* Configure parameters for the join request */

        boolean askForSignInfo = true;
        boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;

        String groupName = "feedca570000";
        String audience = "rs2";
        String cti = "token4JoinMultipleRolesDeriv";
        String asName = "TestAS";
        String clientID = "clientD";

        String gmBaseURI = "coap://localhost/";
        String authzInfoURI = gmBaseURI + "authz-info";
        String joinResourceURI = gmBaseURI + groupName;

        System.out.println("Performing Token post to GM followed by Join request.");
        System.out.println("GM join resource is at: " + joinResourceURI);

        /* Prepare ACE Token generated by the client */

        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 

        //Create a byte string scope for use later
        String gid = new String(groupName);
        String role1 = new String("requester");
        String role2 = new String("responder");

        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
        CBORObject cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(role1);
        cborArrayRoles.Add(role2);
        cborArrayScope.Add(cborArrayRoles);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();

        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject(audience));
        params.put(Constants.CTI, CBORObject.FromObject(cti.getBytes(Constants.charset))); //Need different CTIs
        params.put(Constants.ISS, CBORObject.FromObject(asName));

        CBORObject osc = CBORObject.NewMap();
        byte[] clientId = clientID.getBytes(Constants.charset); //Need different client IDs
        osc.Add(Constants.OS_CLIENTID, clientId);
        osc.Add(Constants.OS_MS, keyCnf);
        byte[] serverId = audience.getBytes(Constants.charset);
        osc.Add(Constants.OS_SERVERID, serverId);

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Security_Context, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());

        /* Post Token to GM */

        System.out.println("Performing Token request to GM. Assuming response from AS was: " + payload.toString());

        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(authzInfoURI, asRes, askForSignInfo, askForPubKeyEnc);

        /* Check response from GM to Token post */

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(OscoreCtxDbSingleton.getInstance().getContext(joinResourceURI));

        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());

        System.out.println("Receved response from GM to Token post: " + rsPayload.toString());

        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()

        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
		byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();

        @SuppressWarnings("unused")
        CBORObject signInfo = null;
        @SuppressWarnings("unused")
        CBORObject pubKeyEnc = null;

        if (askForSignInfo) {
            signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        }

        if (askForPubKeyEnc) {
            pubKeyEnc = rsPayload.get(CBORObject.FromObject(Constants.PUB_KEY_ENC));
        }

        /* Now proceed to build join request to GM */

        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(joinResourceURI, CoAP.DEFAULT_COAP_PORT));

        CBORObject requestPayload = CBORObject.NewMap();

        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));

        if (askForPubKeys) {
            CBORObject getPubKeys = CBORObject.NewArray();
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        }

        if (providePublicKey) {

            // For the time being, the client's public key can be only a COSE Key
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();

            requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());

            // Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);

            // Add the signature computed over (rsnonce | cnonce), using the Client's private key
            PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)))).AsPrivateKey();
            byte [] dataToSign = new byte [gm_sign_nonce.length + cnonce.length];
            System.arraycopy(gm_sign_nonce, 0, dataToSign, 0, gm_sign_nonce.length);
            System.arraycopy(cnonce, 0, dataToSign, gm_sign_nonce.length, cnonce.length);

            byte[] clientSignature = computeSignature(privKey, dataToSign, countersignKeyCurve);

            if (clientSignature != null)
                requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
            else
                Assert.fail("Computed signature is empty");

        }

        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);

        /* Send to join request to GM */

        System.out.println("Performing Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);

        /* Parse response to Join request from GM */

        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

        //The following three lines were useful for generating the Group OSCORE context
        // CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        // Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(keyMap));
        // GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 

        System.out.println("Received response from GM to Join request: " + joinResponse.toString());

        /* Parse the Join response in detail */

        printJoinResponse(joinResponse);

        /* Generate a Group OSCORE security context from the Join response */

        byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);

		// Add checking of the derived context
		TestDtlspClientGroupOSCORE.groupOSCOREContextDeriver(joinResponse);
    }
    

    /**
	 * Compute a signature, using the same algorithm and private key used in the
	 * OSCORE group to join
	 * 
	 * @param privKey private key used to sign
	 * @param dataToSign content to sign
	 * @param countersignKeyCurve the countersignature curve to use
	 * @return the computed signature
	 * 
	 */
    public static byte[] computeSignature(PrivateKey privKey, byte[] dataToSign, int countersignKeyCurve) {

        Signature mySignature = null;
        byte[] clientSignature = null;

        try {
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
                mySignature = Signature.getInstance("SHA256withECDSA");
            else if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
                mySignature = Signature.getInstance("NonewithEdDSA", "EdDSA");
            else {
                // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
                Assert.fail("Unsupported signature algorithm");
            }

        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsupported signature algorithm");
        }
        catch (NoSuchProviderException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsopported security provider for signature computing");
        }

        try {
            if (mySignature != null)
                mySignature.initSign(privKey);
            else
                Assert.fail("Signature algorithm has not been initialized");
        }
        catch (InvalidKeyException e) {
            System.out.println(e.getMessage());
            Assert.fail("Invalid key excpetion - Invalid private key");
        }

        try {
            if (mySignature != null) {
                mySignature.update(dataToSign);
                clientSignature = mySignature.sign();
            }
        } catch (SignatureException e) {
            System.out.println(e.getMessage());
            Assert.fail("Failed signature computation");
        }

        return clientSignature;

    }
    
    /**
     * Parse a received Group OSCORE join response and print the information in it.
     * 
     * @param joinResponse the join response
     */
    public static void printJoinResponse(CBORObject joinResponse) {
        
        //Parse the join response generally

        System.out.println();
        System.out.println("Join response contents: ");

        System.out.print("KTY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.GKTY)));

        System.out.print("KEY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KEY)));

        System.out.print("PROFILE: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PROFILE)));

        System.out.print("EXP: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.EXP)));

        System.out.print("PUB_KEYS: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)));

        System.out.print("NUM: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.NUM)));

        //Parse the KEY parameter

        CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        System.out.println();
        System.out.println("KEY map contents: ");

        System.out.print("ms: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)));

        System.out.print("clientId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)));

        System.out.print("serverId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.serverId)));

        System.out.print("hkdf: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));

        System.out.print("alg: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));

        System.out.print("salt: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)));

        System.out.print("contextId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)));


        System.out.print("cs_alg: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        System.out.print("cs_params: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));

        System.out.print("cs_key_params: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));

        System.out.print("cs_key_enc: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));

        //Parse the PUB_KEYS parameter

        System.out.println();
        System.out.println("PUB_KEYS contents: ");

        byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);

        for(int i = 0 ; i < coseKeySetArray.size() ; i++) {

            CBORObject key_param = coseKeySetArray.get(i);

            System.out.println("Key " + i + ": " + key_param.toString());
        }
    }

}
