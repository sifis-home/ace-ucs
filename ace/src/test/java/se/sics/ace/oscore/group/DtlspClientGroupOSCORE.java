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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
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
 * This should be run with as TestDtlspRSGroupOSCORE server.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class DtlspClientGroupOSCORE {

    private static byte[] key128
        = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static byte[] key128a 
        = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    // Private and public key to be used in the OSCORE group (ECDSA_256)
    //private static String groupKeyPair = "piJYIBZKbV1Ll/VtH2ChKBHVXeegVeusYWTJ75MCy8v/Hwq+I1ggO+AEdZm0KqRLj4oPqI1NoRaXtY2fzE45RD6YQ78jBYYDJgECIVgg6Pmo1YUKUzzaJLn6ih7ik/ag4egeHlYKZP8TTWX37OwgAQ==";
    
    // Private and public key to be used in the OSCORE group (EDDSA)
    private static String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
    
    // Public key to be received for the group member with Sender ID 0x52 (ECDSA_256)
    //private static String strPublicKeyPeer1 = "pSJYIF0xJHwpWee30/YveWIqcIL/ATJfyVSeYbuHjCJk30xPAyYhWCA182VgkuEmmqruYmLNHA2dOO14gggDMFvI6kFwKlCzrwECIAE=";
    
    // Public key to be received for the group member with Sender ID 0x52 (EDDSA)
    //private static String strPublicKeyPeer1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    
    // Public key to be received for the group member with Sender ID 0x77 (ECDSA_256)
    //private static String strPublicKeyPeer2 = "pSJYIHbIGgwahy8XMMEDF6tPNhYjj7I6CHGei5grLZMhou99AyYhWCCd+m1j/RUVdhRgt7AtVPjXNFgZ0uVXbBYNMUjMeIbV8QECIAE=";
    
    // Public key to be received for the group member with Sender ID 0x77 (EDDSA)
    //private static String strPublicKeyPeer2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
    
    private static String rsAddrC;
    
    private static CwtCryptoCtx ctx;
    
    public static void main(String[] args) throws Exception {
    	
    	//Install needed cryptography providers
    	org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
        
    	//Setup some needed parameters
        rsAddrC = "coap://localhost/authz-info";
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
    	
        
        //Perform Token post and Join procedure
        postPSKGroupOSCOREMultipleRolesContextDerivation();
    	
    	//Cleans up after the execution
    	new File(TestConfig.testFilePath + "tokens.json").delete();	
    }
   
    // M.T. & Rikard
    /** 
     * Post Token to authz-info with PSK then request
     * for joining an OSCORE Group with multiple roles.
     * This will then be followed by derivation of a
     * Group OSCORE context based on the information
     * received from the GM.
     * 
     * @throws CoseException if COSE key generation fails
     * @throws AceException if ACE processing fails
     * @throws InvalidCipherTextException if using an invalid cipher
     * @throws IllegalStateException
     * @throws IOException for communication failures
     * @throws ConnectorException  for communication failures
     * 
     */
    public static void postPSKGroupOSCOREMultipleRolesContextDerivation() throws CoseException, IllegalStateException, InvalidCipherTextException, AceException, ConnectorException, IOException {
    	
    	OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourPSK";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
               
        Map<Short, CBORObject> params = new HashMap<>();
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("listener");
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
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
                "tokenPostPSKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);
        @SuppressWarnings("unused")
		CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        //CBORObject cbor = CBORObject.FromObject(r.getPayload());
        //Assert.assertNotNull(cbor);
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        c.setURI("coaps://localhost/feedca570000");
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        requestPayload.Add("scope", CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
        	CBORObject getPubKeys = CBORObject.NewArray();
        	requestPayload.Add("get_pub_keys", getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair))).PublicKey();
        	requestPayload.Add("client_cred", publicKey.AsCBOR().EncodeToBytes());
        	
        }
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        //System.out.println("Payload: " + r2.getResponseText());
        //Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        //Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        //Assert.assertEquals(true, joinResponse.ContainsKey("kty"));
        //Assert.assertEquals(CBORType.Number, joinResponse.get("kty").getType());
        // Assume that "Group_OSCORE_Security_Context object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        //Assert.assertEquals(0, joinResponse.get("kty").AsInt32());
        
        //Assert.assertEquals(true, joinResponse.ContainsKey("key"));
        //Assert.assertEquals(CBORType.Map, joinResponse.get("key").getType());
        
        CBORObject myMap = joinResponse.get("key");
        
        // Sanity check
    	//Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)));
        //Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // ECDSA_256
        ////Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        ////Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        
        // EDDSA (Ed25519)
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        //Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        
//    	final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
//                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
//                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
//                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
//    	final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
//                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
//    	final byte[] senderId = new byte[] { (byte) 0x25 };
//    	final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
//    	final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
//    	final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
//    	
//    	final AlgorithmID csAlg;
    	
        Map<KeyKeys, CBORObject> csParamsMap = new HashMap<>();
        Map<KeyKeys, CBORObject> csKeyParamsMap = new HashMap<>();
    	
    	// ECDSA_256
    	//csAlg = AlgorithmID.ECDSA_256;
        //csKeyParamsMap.put(KeyKeys.KeyType, KeyKeys.KeyType_EC2);        
        //csKeyParamsMap.put(KeyKeys.EC2_Curve, KeyKeys.EC2_P256);

    	// EDDSA (Ed25519)
//    	csAlg = AlgorithmID.EDDSA;
        csParamsMap.put(KeyKeys.OKP_Curve, KeyKeys.OKP_Ed25519);
        csKeyParamsMap.put(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
        csKeyParamsMap.put(KeyKeys.OKP_Curve, KeyKeys.OKP_Ed25519);
    	
//        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
//        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
    	
    	//Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.ms)).GetByteString());
    	//Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.clientId)).GetByteString());
    	
        //Assert.assertEquals(CBORObject.FromObject(hkdf), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)));
        //Assert.assertEquals(CBORObject.FromObject(alg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)));
        //Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)).GetByteString());
        //Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.contextId)).GetByteString());
        //Assert.assertEquals(CBORObject.FromObject(csAlg), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.hkdf)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.alg)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.alg, AlgorithmID.AES_CCM_16_64_128);
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.salt)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.rpl)) == false)
        	myMap.Add(GroupOSCORESecurityContextObjectParameters.rpl, CBORObject.FromObject((int)32));        
        
        Map<Short, CBORObject> contextParams = new HashMap<>(GroupOSCORESecurityContextObjectParameters.getParams(myMap));
        GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams); 
        
        //Assert.assertEquals(true, joinResponse.ContainsKey("profile"));
        //Assert.assertEquals(CBORType.Number, joinResponse.get("profile").getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        //Assert.assertEquals(0, joinResponse.get("profile").AsInt32());
        
        //Assert.assertEquals(true, joinResponse.ContainsKey("exp"));
        //Assert.assertEquals(CBORType.Number, joinResponse.get("exp").getType());
        //Assert.assertEquals(1000000, joinResponse.get("exp").AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params))) {
        	//Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)).getType());
            //Assert.assertEquals(CBORObject.FromObject(csParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));
        }
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params))) {
        	//Assert.assertEquals(CBORType.Map, myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)).getType());
            //Assert.assertEquals(CBORObject.FromObject(csKeyParams), myMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));
        }
        
        CBORObject coseKeySetArray = null;
        if (askForPubKeys) {
        	//Assert.assertEquals(true, joinResponse.ContainsKey("pub_keys"));
        	//Assert.assertEquals(CBORType.ByteString, joinResponse.get("pub_keys").getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get("pub_keys").GetByteString();
        	coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        	//Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        	//Assert.assertEquals(2, coseKeySetArray.size());
        	
//        	byte[] peerSenderId;
//        	OneKey peerPublicKey;
//        	byte[] peerSenderIdFromResponse;
        	
//        	peerSenderId = new byte[] { (byte) 0x52 };
//        	peerSenderIdFromResponse = coseKeySetArray.get(0).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
//        	peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
        	//Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
        	////Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
        	////Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
        	////Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
        	////Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
        	
        	// EDDSA (Ed25519)
        	//Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
        	//Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
        	//Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
        	//Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
        	
//        	peerSenderId = new byte[] { (byte) 0x77 };
//        	peerSenderIdFromResponse = coseKeySetArray.get(1).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
//        	peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2)));
        	//Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
        	////Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
        	////Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
        	////Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
        	////Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
        	
        	// EDDSA (Ed25519)
        	//Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
        	//Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
        	//Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
        	//Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
        	
        }
        else {
        	//Assert.assertEquals(false, joinResponse.ContainsKey("pub_keys"));
        }
        
        /* Context derivation below */
        
        //Defining variables to hold the information before derivation
        
        //Algorithm
        AlgorithmID algo = null;
        CBORObject alg_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.alg);
        if(alg_param.getType() == CBORType.TextString) {
        	algo = AlgorithmID.valueOf(alg_param.AsString());
        } else if(alg_param.getType() == CBORType.SimpleValue) {
        	algo = AlgorithmID.FromCBOR(alg_param);
        }
        
        //KDF
        AlgorithmID kdf = null;
        CBORObject kdf_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.hkdf);
        if(kdf_param.getType() == CBORType.TextString) {
        	kdf = AlgorithmID.valueOf(kdf_param.AsString());
        } else if(kdf_param.getType() == CBORType.SimpleValue) {
        	kdf = AlgorithmID.FromCBOR(kdf_param);
        }
        
    	//Algorithm for the countersignature
        AlgorithmID alg_countersign = null;
        CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
        if(alg_countersign_param.getType() == CBORType.TextString) {
        	alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
        } else if(alg_countersign_param.getType() == CBORType.SimpleValue) {
        	alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
        }
        
        //Parameter for the countersignature
        Integer par_countersign = null;
        CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
        if(par_countersign_param.getType() == CBORType.Map) {
        	par_countersign = par_countersign_param.get(KeyKeys.OKP_Curve.name()).AsInt32();
        } else {
        	System.err.println("Unknown par_countersign value!");
        }
        System.out.println("CS_PARAM: " + par_countersign_param.ToJSONString());
        System.out.println("CS_PARAM2: " + par_countersign_param.get(KeyKeys.OKP_Curve.name()));

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
    	if(rpl_param != null && rpl_param.getType() == CBORType.SimpleValue) {
    		rpl = rpl_param.AsInt32();
    	}
    	
    	//Set up private & public keys for sender (not from response but set by client)
    	String sid_private_key_string = groupKeyPair;
    	OneKey sid_private_key;
       	sid_private_key = new OneKey(CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));

    	//Now derive the actual context
    	
    	GroupOSCoreCtx ctx = null;
		try {
			ctx = new GroupOSCoreCtx(master_secret, true, algo, sid, kdf, rpl, 
					master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
		} catch (OSException e) {
			System.err.println("Failed to derive Group OSCORE Context!");
			e.printStackTrace();
		}
		
		//Finally add the recipient contexts from the coseKeySetArray
		for(int i = 0 ; i < coseKeySetArray.size() ; i++) {
			
			CBORObject key_param = coseKeySetArray.get(i);
			
	    	byte[] rid = null;
	    	CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
	    	if(rid_param.getType() == CBORType.ByteString) {
	    		rid = rid_param.GetByteString();
	    	}
			
			OneKey recipient_key = new OneKey(key_param);
			
			ctx.addRecipientContext(rid, recipient_key);
		}
		
		
    }
    
    
}
