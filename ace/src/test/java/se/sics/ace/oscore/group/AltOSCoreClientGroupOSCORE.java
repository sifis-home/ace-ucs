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
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.Utility;

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
 * A client for testing Group Joining over OSCORE.
 * Post a Token to the GM followed by the group join procedure.
 * 
 * This should be run with TestOSCoreRSGroupOSCORE as server.
 * TODO: Re-enable token post
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class AltOSCoreClientGroupOSCORE {
	
	//Sets the port to use
	private final static int GM_PORT = CoAP.DEFAULT_COAP_PORT;
	//Set the hostname/IP of the RS (GM)
	private final static String GM_ADDRESS = "127.0.0.1";
	
   	private final static String uriGM = "coap://" + GM_ADDRESS;
	//Additions for creating a fixed context (from Peter's mail 23/9 -19)
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	
	private final static byte[] master_secret = { 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, (byte) 0x82, (byte) 0x92, (byte) 0xa2,
			 (byte) 0xb2, (byte) 0xc2, (byte) 0xd2, (byte) 0xe2, (byte) 0xf2, 0x22 };
	private final static byte[] master_salt = { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40, (byte) 0x95, 0x7c,
			 (byte) 0x94, 0x46, 0x78, (byte) 0xdb, (byte) 0xf5, 0x6d, 0x3c, 0x3e, 0x2a, 0x76, 0x47, 0x1c, (byte) 0xd7, 0x16 };
	//private final static byte[] context_id = { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
	private final static byte[] sid = new byte[] { 0x43, 0x31 };
	private final static byte[] rid = new byte[] { 0x47, 0x4d };
	//End Additions for creating a fixed context
	
    private static byte[] key128
        = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static byte[] key128a 
        = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    // Private and public key to be used in the OSCORE group (EDDSA)
    private static String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

    private static String rsAddrC;
    private static String rsGroupRes;
    private static String zeroEpochGroupID;
    private static String joinResourcePath;
    
    private static CwtCryptoCtx ctx;
    
    //Use DTLS rather than OSCORE
    private static boolean useDTLS = false;
    
    public static void main(String[] args) throws Exception {

    	//Install needed cryptography providers
    	org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
        
    	//Set OSCORE Context information
    	OSCoreCtx ctxOSCore = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		db.addContext(uriGM, ctxOSCore);
		OSCoreCoapStackFactory.useAsDefault();
		
    	//Setup some needed parameters
        rsAddrC = "coap://" + GM_ADDRESS + ":" + GM_PORT + "/authz-info";

        //zeroEpochGroupID = "feedca570000";
        zeroEpochGroupID = "GRP";
        joinResourcePath = "GM/group-oscore/" + zeroEpochGroupID; 
        if(useDTLS) {
        rsGroupRes = "coaps://" + GM_ADDRESS + ":" + (GM_PORT + 1 ) + "/" + joinResourcePath;
        } else {
        	rsGroupRes = "coap://" + GM_ADDRESS + ":" + GM_PORT + "/" + joinResourcePath;
        }
        
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
     * Goes straight for join request without posting a Token.
     * Using a hardcoded OSCORE context. 
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
        String gid = new String(zeroEpochGroupID);
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
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
        if(!useDTLS) {
        	params.put(Constants.PROFILE, CBORObject.FromObject("coap_oscore"));
        }
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = token.encode(ctx);
        //System.out.println("Posting Token to GM at " + rsAddrC);
        
        //CoapClient tokenPoster = new CoapClient(rsAddrC);
        
        //@SuppressWarnings("unused")
		//CoapResponse r = DTLSProfileRequests.postToken(rsAddrC, payload, null);
        //System.out.println("Sent Token to GM: " + payload.toString());
        ///@SuppressWarnings("unused")
        ///CoapResponse r = tokenPoster.post(payload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        
        ///CBORObject tokenPostResponse = CBORObject.DecodeFromBytes(r.getPayload());
        ///System.out.println("Received Token post response from GM: " + tokenPostResponse.toString());
        
        //Below is section for performing Join request
        CoapClient c;
        if(useDTLS) {
        c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress("localhost", 
                        CoAP.DEFAULT_COAP_SECURE_PORT), 
                kidStr.getBytes(Constants.charset),
                key);
        } else {
        	c = new CoapClient();	
        }
        
        System.out.println("Performing Join request using OSCORE to GM at " + rsGroupRes);
        c.setURI(rsGroupRes);
        
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
        	
        }
        
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);
        if(!useDTLS) {
        	joinReq.getOptions().setOscore(Bytes.EMPTY); //Enable OSCORE for Join request
        }
        
        //CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), MediaTypeRegistry.APPLICATION_CBOR);
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        System.out.println("Sent Join request to GM: " + requestPayload.ToJSONString());
        CoapResponse r2 = c.advanced(joinReq);
        
        byte[] responsePayload = r2.getPayload();

        System.out.println("Received response to Join req from GM: " + r2.getResponseText());
        
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        System.out.println("Received response to Join req from GM: " + joinResponse.ToJSONString());

        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
//        if(myMap.size() != 9) {
//        	System.out.println("Received bad response from GM: " + r2.getResponseText());
//        } else {
//        	System.out.println("Received Join response from GM: " + joinResponse.toString());
//        }

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
        
        CBORObject coseKeySetArray = null;
        if (askForPubKeys) {
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte); 	
        }
        else {
        	System.err.println("Joing response did not contain pub_keys!");
        }
        
        /* Group OSCORE Context derivation below */
        
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
		
		//Print information about the created context
		System.out.println();
		System.out.println("Generated Group OSCORE Context from received information:");
		Utility.printContextInfo(ctx);
		
		
    }
    
    
}