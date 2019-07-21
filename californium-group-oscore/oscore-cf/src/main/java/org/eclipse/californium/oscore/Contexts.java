package org.eclipse.californium.oscore;

import java.util.HashMap;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

public class Contexts { //FIXME: Add cs key params
	
	//General parameters
	
	final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	final static int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	final static int replay_size = 32;
	
	//Common Context
	public static class Common {
	
		final static byte[] master_secret = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0, (byte) 0xf0, 0x01 };
		final static byte[] master_salt = { (byte) 0xe9, (byte) 0xc7, (byte) 0x9a, 0x22, 0x32, (byte) 0x87, 0x36, 0x04 };
		final static byte[] id_context = new byte[] { 0x73, (byte) 0xbc, 0x3f, 0x12, 0x00, 0x71, 0x2a, 0x3d };
		
		final static AlgorithmID alg_countersign = AlgorithmID.EDDSA;
		final static Integer par_countersign = ED25519; //Ed25519
		
	}

	//Contexts for my clients and servers (Based on Entity #2)
	
	//Client
	public static class Client {
	
		final static byte[] sid = new byte[] { (byte) 0xB1 };
		
		final static byte[] data = new byte[] { (byte) 0xA4, (byte) 0x01, (byte) 0x01, (byte) 0x20, (byte) 0x06, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0x90, (byte) 0xF2, (byte) 0x8C, (byte) 0x4C, (byte) 0xC6, (byte) 0x3A, (byte) 0x56, (byte) 0x57, (byte) 0x4F, (byte) 0x18, (byte) 0x73, (byte) 0xB8, (byte) 0x02, (byte) 0xB5, (byte) 0x87, (byte) 0xF9, (byte) 0xCE, (byte) 0x05, (byte) 0xE7, (byte) 0x18, (byte) 0x88, (byte) 0x7B, (byte) 0x34, (byte) 0x11, (byte) 0xE8, (byte) 0xEC, (byte) 0x97, (byte) 0xB9, (byte) 0xC2, (byte) 0x8E, (byte) 0x72, (byte) 0x27, (byte) 0x23, (byte) 0x58, (byte) 0x20, (byte) 0x73, (byte) 0x2B, (byte) 0xA0, (byte) 0xEF, (byte) 0x6C, (byte) 0xAC, (byte) 0x00, (byte) 0xA9, (byte) 0x1E, (byte) 0x97, (byte) 0xBD, (byte) 0xA1, (byte) 0x8E, (byte) 0x1E, (byte) 0x4D, (byte) 0x94, (byte) 0xC4, (byte) 0xC7, (byte) 0x59, (byte) 0x88, (byte) 0x67, (byte) 0x6B, (byte) 0xE4, (byte) 0x3B, (byte) 0x7B, (byte) 0x76, (byte) 0x64, (byte) 0xA1, (byte) 0xD5, (byte) 0xB2, (byte) 0x65, (byte) 0x1F };
		public static CBORObject signing_key_cbor = CBORObject.DecodeFromBytes(data);
	}
	
	//Server #1
	public static class Server_1 {
		
		final static byte[] sid = new byte[] { (byte) 0xB2 };
	
		public static CBORObject signing_key_cbor = Contexts.Client.signing_key_cbor; //Same as Client key
	}
	
	//Server #2
	public static class Server_2 {
		
		final static byte[] sid = new byte[] { (byte) 0xB3 };
		
		public static CBORObject signing_key_cbor = Contexts.Client.signing_key_cbor; //Same as Client key
	}
	
	//Context for external client/servers
	
	//Jim
	public static class Jim {
		final static byte client_rid[] = new byte[] { (byte) 0xA1 };
		final static byte server_1_rid[] = new byte[] { (byte) 0xA2 };
		final static byte server_2_rid[] = new byte[] { (byte) 0xA3 };
		
		public static byte[] data = new byte[] { (byte) 0xA4, (byte) 0x01, (byte) 0x01, (byte) 0x20, (byte) 0x06, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0x4C, (byte) 0x5E, (byte) 0x5A, (byte) 0x89, (byte) 0x8A, (byte) 0xFC, (byte) 0x77, (byte) 0xD9, (byte) 0xC9, (byte) 0x07, (byte) 0x73, (byte) 0xD9, (byte) 0xB4, (byte) 0xF5, (byte) 0xE7, (byte) 0xB3, (byte) 0x78, (byte) 0x60, (byte) 0x57, (byte) 0x53, (byte) 0xF9, (byte) 0xBA, (byte) 0x9E, (byte) 0x8A, (byte) 0x62, (byte) 0x48, (byte) 0x8C, (byte) 0x64, (byte) 0xE1, (byte) 0xA5, (byte) 0x24, (byte) 0xB0, (byte) 0x23, (byte) 0x58, (byte) 0x20, (byte) 0xC9, (byte) 0xAF, (byte) 0xCF, (byte) 0x66, (byte) 0x10, (byte) 0xBA, (byte) 0xB6, (byte) 0x9A, (byte) 0x7E, (byte) 0x72, (byte) 0xB7, (byte) 0x8B, (byte) 0x6D, (byte) 0x36, (byte) 0x4B, (byte) 0xE8, (byte) 0x6F, (byte) 0x12, (byte) 0xCF, (byte) 0x29, (byte) 0x35, (byte) 0x23, (byte) 0xDA, (byte) 0x51, (byte) 0x43, (byte) 0x3B, (byte) 0x09, (byte) 0xA7, (byte) 0x99, (byte) 0xFF, (byte) 0x0F, (byte) 0x62 };
		public static CBORObject public_key_cbor = CBORObject.DecodeFromBytes(data);
	}
	
	//Peter
	public static class Peter {
		final static byte client_rid[] = new byte[] { (byte) 0xC1 };		
		final static byte server_1_rid[] = new byte[] { (byte) 0xC2 };
		final static byte server_2_rid[] = new byte[] { (byte) 0xC3 };
		
		public static byte[] data = new byte[] { (byte) 0xA3, (byte) 0x01, (byte) 0x01, (byte) 0x20, (byte) 0x06, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0x50, (byte) 0x8A, (byte) 0xFC, (byte) 0x1C, (byte) 0x29, (byte) 0x03, (byte) 0x7E, (byte) 0xF3, (byte) 0x61, (byte) 0x4D, (byte) 0x63, (byte) 0xAF, (byte) 0x87, (byte) 0xE1, (byte) 0xEA, (byte) 0x31, (byte) 0xD8, (byte) 0x91, (byte) 0xD7, (byte) 0x6B, (byte) 0x1F, (byte) 0x90, (byte) 0x60, (byte) 0x98, (byte) 0xAF, (byte) 0x8F, (byte) 0xA3, (byte) 0x9B, (byte) 0xBE, (byte) 0x87, (byte) 0x40, (byte) 0x19 };
		public static CBORObject public_key_cbor = CBORObject.DecodeFromBytes(data);
	}


	/* Methods dealing with stored information about recipient IDs and associated keys */
	public static OneKey getKeyForRecipient(byte[] recipientID) throws CoseException {
		return new OneKey(recipientInfo.get(new ByteId(recipientID)));
	}
	
	//List of recipient ID:s accessible with associated public keys
	private static HashMap<ByteId, CBORObject> recipientInfo = new HashMap<ByteId, CBORObject>();
	
	//Method to fill the list of recipients and associated keys
	public static void fillRecipientInfo() {
		recipientInfo.put(new ByteId(Jim.client_rid), Jim.public_key_cbor);
		recipientInfo.put(new ByteId(Jim.server_1_rid), Jim.public_key_cbor);
		recipientInfo.put(new ByteId(Jim.server_2_rid), Jim.public_key_cbor);
		
		recipientInfo.put(new ByteId(Peter.client_rid), Peter.public_key_cbor);
		recipientInfo.put(new ByteId(Peter.server_1_rid), Peter.public_key_cbor);
		recipientInfo.put(new ByteId(Peter.server_2_rid), Peter.public_key_cbor);
		
		//Add my own keys
		recipientInfo.put(new ByteId(Client.sid), Client.signing_key_cbor);
		recipientInfo.put(new ByteId(Server_1.sid), Client.signing_key_cbor);
		recipientInfo.put(new ByteId(Server_2.sid), Client.signing_key_cbor);
	}
	/* End Methods dealing with stored information about recipient IDs and associated keys */

}
