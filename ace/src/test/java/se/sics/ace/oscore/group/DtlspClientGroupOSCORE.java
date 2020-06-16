/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSException;
import org.junit.Assert;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;

/**
 * A client running the DTLS profile.
 * Post a Token to the GM followed by the group join procedure.
 * 
 * This should be run with TestDtlspRSGroupOSCORE as server.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class DtlspClientGroupOSCORE {

    private static byte[] key128
        = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static byte[] key128a 
        = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    private static String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

    private static CwtCryptoCtx ctx;
    
    public static void main(String[] args) throws Exception {
    	
    	//Install needed cryptography providers
    	org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();

    	COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        //Perform Token post and Join procedure
        performJoinDTLSProfile();
    	
    	//Cleans up after the execution
    	new File(TestConfig.testFilePath + "tokens.json").delete();	
    }
    
    // M.T. & Rikard
    /** 
    * Test post to authz-info with PSK then request
    * for joining an OSCORE Group with multiple roles.
    * This will then be followed by derivation of a
    * Group OSCORE context based on the information
    * received from the GM.
    * @throws CoseException 
    * @throws AceException 
    * @throws InvalidCipherTextException 
    * @throws IllegalStateException 
    * @throws IOException 
    * @throws ConnectorException 
    */
    public static void performJoinDTLSProfile() throws IllegalStateException, InvalidCipherTextException, CoseException, AceException, OSException, ConnectorException, IOException {

        /* Configure parameters for the join request */

        boolean askForSignInfo = true;
        boolean askForPubKeyEnc = true;
        boolean askForPubKeys = true;
        boolean providePublicKey = true;
        
        String groupName = "feedca570000";
        String gmHostname = "localhost";
        
        String authzInfoURI = "coap://" + gmHostname + "/authz-info";
        String joinResourceURI = "coaps://" + gmHostname + "/" + groupName;

        System.out.println("Performing Token post to GM followed by Join request.");
        System.out.println("GM join resource is at: " + joinResourceURI);

        /* Prepare ACE Token generated by the client */

        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourPSK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
               
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String(groupName);
        String role1 = new String("requester");
        String role2 = new String("responder");
        
        // Client's asymmetric key pair
        OneKey asymmetric = OneKey.generateKey(AlgorithmID.ECDSA_256);
        String asymmetricKidStr = "ClientKeyPair";
        CBORObject asymmetricKid = CBORObject.FromObject(
                asymmetricKidStr.getBytes(Constants.charset));
        asymmetric.add(KeyKeys.KeyId, asymmetricKid);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
        CBORObject cborArrayRoles = CBORObject.NewArray();
        cborArrayRoles.Add(role1);
        cborArrayRoles.Add(role2);
        cborArrayScope.Add(cborArrayRoles);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostPSKGOMRDerivC".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
        if (askForSignInfo)
            payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        if (askForPubKeyEnc)
            payload.Add(Constants.PUB_KEY_ENC, CBORObject.Null);

        /* Post Token to GM */

        System.out.println("Performing Token request to GM. Assuming response from AS was: " + payload.toString());

        CoapResponse rsRes = DTLSProfileRequests.postToken(authzInfoURI, payload, null);

        /* Check response from GM to Token post */

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));

        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());

        System.out.println("Receved response from GM to Token post: " + rsPayload.toString());

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

        CoapClient c = DTLSProfileRequests.getPskClient(new InetSocketAddress(gmHostname, CoAP.DEFAULT_COAP_SECURE_PORT), kidStr.getBytes(Constants.charset), key);
        c.setURI(joinResourceURI);

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

            byte[] clientSignature = OscorepClient2RSGroupOSCORE.computeSignature(privKey, dataToSign, countersignKeyCurve);

            if (clientSignature != null)
                requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
            else
                Assert.fail("Computed signature is empty");

        }

        Request joinReq = new Request(Code.POST, Type.CON);
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

        OscorepClient2RSGroupOSCORE.printJoinResponse(joinResponse);

        /* Generate a Group OSCORE security context from the Join response */

        byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);

		// (Readd) GroupOSCoreCtx groupOscoreCtx =
		// OscorepClient2RSGroupOSCORE.generateGroupOSCOREContext(contextObject,
		// coseKeySetArray);

        System.out.println();
        //System.out.println("Generated Group OSCORE Context:");
		// (Readd) Utility.printContextInfo(groupOscoreCtx);

    }
}
