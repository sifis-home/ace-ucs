package se.sics.ace.oscore.group;

import static org.junit.Assert.assertNotNull;

import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.groscore.OSException;
import org.eclipse.californium.groscore.group.GroupCtx;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

public class GroupOSCOREUtils {

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

	/**
	 * Standalone method for deriving a Group OSCORE context from a join
	 * response.
	 * 
	 * @param joinResponse the CBORObject with the join response
	 * @param senderKeyPair the key of the joining member
	 * @return the created Group OSCORE context
	 * @throws CoseException on derivation failure
	 * @throws AceException
	 */
	public static GroupCtx groupOSCOREContextDeriver(CBORObject joinResponse,
			String senderKeyPair)
			throws CoseException, AceException {
	
		byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
		CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
	
		CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
		Map<Short, CBORObject> contextParams = new HashMap<>(OSCORESecurityContextObjectParameters.getParams(myMap));
		GroupOSCORESecurityContextObject contextObject = new GroupOSCORESecurityContextObject(contextParams);
	
		/* Group OSCORE Context derivation below */
	
		// Defining variables to hold the information before derivation
	
		// Algorithm
		AlgorithmID algo = null;
		CBORObject alg_param = contextObject.getParam(OSCORESecurityContextObjectParameters.alg);
		if (alg_param.getType() == CBORType.TextString) {
			algo = AlgorithmID.valueOf(alg_param.AsString());
		} else if (alg_param.getType() == CBORType.Integer) {
			algo = AlgorithmID.FromCBOR(alg_param);
		}
	
		// KDF
		AlgorithmID kdf = null;
		CBORObject kdf_param = contextObject.getParam(OSCORESecurityContextObjectParameters.hkdf);
		if (kdf_param.getType() == CBORType.TextString) {
			kdf = AlgorithmID.valueOf(kdf_param.AsString());
		} else if (kdf_param.getType() == CBORType.Integer) {
			kdf = AlgorithmID.FromCBOR(kdf_param);
		}
	
		// Algorithm for the countersignature
		AlgorithmID alg_countersign = null;
		CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
		if (alg_countersign_param.getType() == CBORType.TextString) {
			alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
		} else if (alg_countersign_param.getType() == CBORType.Integer) {
			alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
		}
	
		// Parameter for the par countersign parameter
		CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
		if (par_countersign_param.getType() != CBORType.Array) {
			System.err.println("Unknown par_countersign value!");
			Assert.fail();
		}
		// Parse the array
		Collection<CBORObject> par_countersign_collection = par_countersign_param.getValues();
		CBORObject[] outerArrayPar = par_countersign_collection
				.toArray(new CBORObject[par_countersign_collection.size()]);
	
		int[][] par_countersign = new int[outerArrayPar.length][];
		for (int i = 0; i < outerArrayPar.length; i++) {
			CBORObject innerArrayCbor = outerArrayPar[i];
	
			if (innerArrayCbor.getType() == CBORType.Array) {
				Collection<CBORObject> innerArrayCollection = innerArrayCbor.getValues();
	
				CBORObject[] innerArray = innerArrayCollection.toArray(new CBORObject[innerArrayCollection.size()]);
	
				par_countersign[i] = new int[innerArray.length];
				for (int n = 0; n < innerArray.length; n++) {
					par_countersign[i][n] = innerArray[n].AsInt32();
				}
			} else {
				par_countersign[i] = new int[1];
				par_countersign[i][0] = innerArrayCbor.AsInt32();
			}
		}
	
		// Parameter for the par countersign key parameter
		CBORObject par_countersign_key_param = contextObject
				.getParam(GroupOSCORESecurityContextObjectParameters.cs_key_params);
		if (par_countersign_key_param.getType() != CBORType.Array) {
			System.err.println("Unknown par_countersign_key value!");
			Assert.fail();
		}
		// Parse the array
		Collection<CBORObject> par_countersign_key_collection = par_countersign_key_param.getValues();
		CBORObject[] arrayKey = par_countersign_key_collection
				.toArray(new CBORObject[par_countersign_key_collection.size()]);
	
		int[] par_countersign_key = new int[arrayKey.length];
		for (int i = 0; i < arrayKey.length; i++) {
			par_countersign_key[i] = arrayKey[i].AsInt32();
		}
	
		// Master secret
		CBORObject master_secret_param = contextObject.getParam(OSCORESecurityContextObjectParameters.ms);
		byte[] master_secret = null;
		if (master_secret_param.getType() == CBORType.ByteString) {
			master_secret = master_secret_param.GetByteString();
		}
	
		// Master salt
		CBORObject master_salt_param = contextObject.getParam(OSCORESecurityContextObjectParameters.salt);
		byte[] master_salt = null;
		if (master_salt_param.getType() == CBORType.ByteString) {
			master_salt = master_salt_param.GetByteString();
		}
	
		// Sender ID
		byte[] sid = null;
		CBORObject sid_param = contextObject.getParam(OSCORESecurityContextObjectParameters.clientId);
		if (sid_param.getType() == CBORType.ByteString) {
			sid = sid_param.GetByteString();
		}
	
		// Group ID / Context ID
		CBORObject group_identifier_param = contextObject.getParam(OSCORESecurityContextObjectParameters.contextId);
		byte[] group_identifier = null;
		if (group_identifier_param.getType() == CBORType.ByteString) {
			group_identifier = group_identifier_param.GetByteString();
		}
	
		// RPL (replay window information)
		int rpl = 32; // Default value
	
		// Check that all values are defined
		assertNotNull(group_identifier);
		assertNotNull(sid);
		assertNotNull(algo);
		assertNotNull(master_salt);
		assertNotNull(master_secret);
		assertNotNull(par_countersign);
		assertNotNull(par_countersign_key);
		assertNotNull(rpl);
		assertNotNull(kdf);
		assertNotNull(alg_countersign);
	
		// Converts AlgorithmID parameters to those from Cose in Californium
		int algInt = algo.AsCBOR().AsInt32();
		CBORObject algCbor = CBORObject.FromObject(algInt);
		org.eclipse.californium.grcose.AlgorithmID algCose = null;
		try {
			algCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(algCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		int hkdfInt = kdf.AsCBOR().AsInt32();
		CBORObject hkdfCbor = CBORObject.FromObject(hkdfInt);
		org.eclipse.californium.grcose.AlgorithmID hkdfCose = null;
		try {
			hkdfCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(hkdfCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		int algCsInt = alg_countersign.AsCBOR().AsInt32();
		CBORObject algCsCbor = CBORObject.FromObject(algCsInt);
		org.eclipse.californium.grcose.AlgorithmID algCsCose = null;
		try {
			algCsCose = org.eclipse.californium.grcose.AlgorithmID.FromCBOR(algCsCbor);
		} catch (org.eclipse.californium.grcose.CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		// Derive the Group OSCORE context
		org.eclipse.californium.groscore.group.GroupCtx groupCtx = new org.eclipse.californium.groscore.group.GroupCtx(
				master_secret, master_salt, algCose, hkdfCose, group_identifier, algCsCose, par_countersign,
				par_countersign_key);
	
		// Set up private & public keys for sender (not from response but set by
		// client)
		String sid_private_key_string = senderKeyPair;
		org.eclipse.californium.grcose.OneKey senderFullKey = null;
		try {
			senderFullKey = new org.eclipse.californium.grcose.OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));
		} catch (org.eclipse.californium.grcose.CoseException e) {
			System.err.println("Failed to decode sender key!");
			e.printStackTrace();
		}
	
		// Add the sender context
		try {
			groupCtx.addSenderCtx(sid, senderFullKey);
		} catch (OSException e) {
			System.err.println("Failed to create sender context!");
			e.printStackTrace();
		}
	
		// Add the recipient contexts from the coseKeySetArray
		byte[] rid = null;
		for (int i = 0; i < coseKeySetArray.size(); i++) {
	
			CBORObject key_param = coseKeySetArray.get(i);
	
			rid = null;
			CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
			if (rid_param.getType() == CBORType.ByteString) {
				rid = rid_param.GetByteString();
			}
	
			org.eclipse.californium.grcose.OneKey recipientPublicKey = null;
			try {
				recipientPublicKey = new org.eclipse.californium.grcose.OneKey(key_param);
			} catch (org.eclipse.californium.grcose.CoseException e) {
				System.err.println("Failed to decode recipient key!");
	
				e.printStackTrace();
			}
			try {
				groupCtx.addRecipientCtx(rid, rpl, recipientPublicKey);
			} catch (OSException e) {
				System.err.println("Failed to create recipient context!");
				e.printStackTrace();
			}
		}
	
		// Return the created group context
		return groupCtx;
	}

}
