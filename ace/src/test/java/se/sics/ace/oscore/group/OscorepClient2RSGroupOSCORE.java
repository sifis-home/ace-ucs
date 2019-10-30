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

import javax.xml.bind.DatatypeConverter;

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
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

/**
 * An application for the OSCORE profile interactions between client and server.
 * Using the OSCORE ACE profile.
 * 
 * Posts a token to the GM and then proceeds to send a join request followed
 * by printing the received join response.
 * 
 * Use this client with the server TestOscorepRSGroupOSCORE
 * 
 * If a Group OSCORE context should be derived that can be done by using code from
 * the JUnit test testSuccessGroupOSCOREMultipleRolesContextDerivation in
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
            performJoin();
        } catch (IllegalStateException | InvalidCipherTextException | CoseException | AceException | OSException
                | ConnectorException | IOException e) {
            System.err.print("Join procedure failed: ");
            e.printStackTrace();
        }
    }

    // M.T. & Rikard
    /**
     * Post to Authz-Info, then perform join request using multiple roles.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws OSException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    public static void performJoin() throws IllegalStateException, InvalidCipherTextException, CoseException, AceException, OSException, ConnectorException, IOException {

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
        byte[] gm_sign_nonce = rsPayload.get(CBORObject.FromObject(Constants.RSNONCE)).GetByteString();

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

            byte[] clientSignature = computeSignature(privKey, dataToSign);

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

        CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

        //The following two lines are useful for generating the Group OSCORE context
        Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(keyMap));
        GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 

        System.out.println("Receved response from GM to Join request: " + joinResponse.toString());

        /* Parse the Join response in detail */

        //Parse the join response generally

        System.out.println();
        System.out.println("Join response contents: ");

        System.out.print("KTY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KTY)));

        System.out.print("KEY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KEY)));

        System.out.print("PROFILE: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PROFILE)));

        System.out.print("EXP: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.EXP)));

        System.out.print("PUB_KEYS: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)));

        //Parse the KEY parameter

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

        System.out.print("rpl: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));


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

        /* Generate a Group OSCORE security context from the Join response */

        GroupOSCoreCtx groupOscoreCtx = generateGroupOSCOREContext(contextObject, coseKeySetArray);

        System.out.println();
        //System.out.println("Generated Group OSCORE Context:");
        Utility.printContextInfo(groupOscoreCtx);

    }

    /**
     * Compute a signature, using the same algorithm and private key used in the OSCORE group to join
     * 
     * @param privKey  private key used to sign
     * @param dataToSign  content to sign

     */
    public static byte[] computeSignature(PrivateKey privKey, byte[] dataToSign) {

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
     * Generate a Group OSCORE Security context from material
     * received in a Join response.
     * 
     * @param contextObject holds the information in the Join response
     * @param CBORObject coseKeySetArray holds information about public keys from the Join response
     * 
     * @throws CoseException 
     */
    public static GroupOSCoreCtx generateGroupOSCOREContext(GroupOSCORESecurityContextObject contextObject, CBORObject coseKeySetArray) throws CoseException {
        //Defining variables to hold the information before derivation

        //Algorithm
        AlgorithmID algo = null;
        CBORObject alg_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.alg);
        if(alg_param.getType() == CBORType.TextString) {
            algo = AlgorithmID.valueOf(alg_param.AsString());
        } else if(alg_param.getType() == CBORType.Number) {
            algo = AlgorithmID.FromCBOR(alg_param);
        }

        //KDF
        AlgorithmID kdf = null;
        CBORObject kdf_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.hkdf);
        if(kdf_param.getType() == CBORType.TextString) {
            kdf = AlgorithmID.valueOf(kdf_param.AsString());
        } else if(kdf_param.getType() == CBORType.Number) {
            kdf = AlgorithmID.FromCBOR(kdf_param);
        }

        //Algorithm for the countersignature
        AlgorithmID alg_countersign = null;
        CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
        if(alg_countersign_param.getType() == CBORType.TextString) {
            alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
        } else if(alg_countersign_param.getType() == CBORType.Number) {
            alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
        }

        //Parameter for the countersignature
        Integer par_countersign = null;
        CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
        if(par_countersign_param.getType() == CBORType.Map) {
            par_countersign = par_countersign_param.get(KeyKeys.OKP_Curve.AsCBOR()).AsInt32();
            //TODO: Change like this in other places too?
        } else {
            System.err.println("Unknown par_countersign value!");
        }

        //Master secret
        CBORObject master_secret_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.ms);
        byte[] master_secret = null;
        if(master_secret_param.getType() == CBORType.ByteString) {
            master_secret = master_secret_param.GetByteString();
        }

        //Master salt
        CBORObject master_salt_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.salt);
        byte[] master_salt = null;
        if(master_salt_param.getType() == CBORType.ByteString) {
            master_salt = master_salt_param.GetByteString();
        }

        //Sender ID
        byte[] sid = null;
        CBORObject sid_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.clientId);
        if(sid_param.getType() == CBORType.ByteString) {
            sid = sid_param.GetByteString();
        }

        //Group ID / Context ID
        CBORObject group_identifier_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.contextId);
        byte[] group_identifier = null;
        if(group_identifier_param.getType() == CBORType.ByteString) {
            group_identifier = group_identifier_param.GetByteString();
        }

        //RPL (replay window information)
        CBORObject rpl_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.rpl);
        int rpl = 32; //Default value
        if(rpl_param != null && rpl_param.getType() == CBORType.Number) {
            rpl = rpl_param.AsInt32();
        }

        //Set up private & public keys for sender (not from response but set by client)
        String sid_private_key_string = groupKeyPair;
        OneKey sid_private_key;
        sid_private_key = new OneKey(CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));

        //Now derive the actual context

        GroupOSCoreCtx groupOscoreCtx = null;
        try {
            groupOscoreCtx = new GroupOSCoreCtx(master_secret, true, algo, sid, kdf, rpl, 
                    master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
        } catch (OSException e) {
            System.err.println("Failed to derive Group OSCORE Context!");
            e.printStackTrace();
        }

        Assert.assertNotNull(groupOscoreCtx);

        //Finally add the recipient contexts from the coseKeySetArray
        for(int i = 0 ; i < coseKeySetArray.size() ; i++) {

            CBORObject key_param = coseKeySetArray.get(i);

            byte[] rid = null;
            CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
            if(rid_param.getType() == CBORType.ByteString) {
                rid = rid_param.GetByteString();
            }

            OneKey recipient_key = new OneKey(key_param);

            groupOscoreCtx.addRecipientContext(rid, recipient_key);
        }
        Assert.assertEquals(groupOscoreCtx.getRecipientContexts().size(), 2);
        //System.out.println("Generated Group OSCORE Context:");
        //Utility.printContextInfo(groupOscoreCtx);

        return groupOscoreCtx;
    }
}
