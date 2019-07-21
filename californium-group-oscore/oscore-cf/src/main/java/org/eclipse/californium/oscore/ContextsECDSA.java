package org.eclipse.californium.oscore;

import java.util.HashMap;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

public class ContextsECDSA { //FIXME: Add cs key params
	
	//General parameters
	
	final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	final static int ECDSA = 0x26; //FIXME
	final static int replay_size = 32;
	
	//Common Context
	public static class Common {
	
		final static byte[] master_secret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10 };
		final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
		final static byte[] id_context = new byte[] { (byte) 0x37, (byte) 0xcb, (byte) 0xf3, (byte) 0x21, (byte) 0x00, (byte) 0x17, (byte) 0xa2, (byte) 0xd3 };
		
		final static AlgorithmID alg_countersign = AlgorithmID.ECDSA_256;
		final static Integer par_countersign = ECDSA;
		
	}

	//Contexts for my clients and servers (Based on Entity #2)
	
	//Client
	public static class Client {
	
		final static byte[] sid = new byte[] { (byte) 0xB1 };
		
		//{1: 2, -1: 1, -2: h'5BC9E40487130A030D37F8162A17EF14CC9E96019A307DBADC90691C563D766B', -3: h'1D6EB75E5585C1B19051A84DCC7608B604095BE857BA37727D65343FEF616DC3', -4: h'BB39276D3A04E14E4421A56689F7CAFEC1D08DF3029CB7CED968283A084B7E38'}
		final static byte[] data = new byte[] { (byte) 0xA5, (byte) 0x01, (byte) 0x02, (byte) 0x20, (byte) 0x01, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0x5B, (byte) 0xC9, (byte) 0xE4, (byte) 0x04, (byte) 0x87, (byte) 0x13, (byte) 0x0A, (byte) 0x03, (byte) 0x0D, (byte) 0x37, (byte) 0xF8, (byte) 0x16, (byte) 0x2A, (byte) 0x17, (byte) 0xEF, (byte) 0x14, (byte) 0xCC, (byte) 0x9E, (byte) 0x96, (byte) 0x01, (byte) 0x9A, (byte) 0x30, (byte) 0x7D, (byte) 0xBA, (byte) 0xDC, (byte) 0x90, (byte) 0x69, (byte) 0x1C, (byte) 0x56, (byte) 0x3D, (byte) 0x76, (byte) 0x6B, (byte) 0x22, (byte) 0x58, (byte) 0x20, (byte) 0x1D, (byte) 0x6E, (byte) 0xB7, (byte) 0x5E, (byte) 0x55, (byte) 0x85, (byte) 0xC1, (byte) 0xB1, (byte) 0x90, (byte) 0x51, (byte) 0xA8, (byte) 0x4D, (byte) 0xCC, (byte) 0x76, (byte) 0x08, (byte) 0xB6, (byte) 0x04, (byte) 0x09, (byte) 0x5B, (byte) 0xE8, (byte) 0x57, (byte) 0xBA, (byte) 0x37, (byte) 0x72, (byte) 0x7D, (byte) 0x65, (byte) 0x34, (byte) 0x3F, (byte) 0xEF, (byte) 0x61, (byte) 0x6D, (byte) 0xC3, (byte) 0x23, (byte) 0x58, (byte) 0x20, (byte) 0xBB, (byte) 0x39, (byte) 0x27, (byte) 0x6D, (byte) 0x3A, (byte) 0x04, (byte) 0xE1, (byte) 0x4E, (byte) 0x44, (byte) 0x21, (byte) 0xA5, (byte) 0x66, (byte) 0x89, (byte) 0xF7, (byte) 0xCA, (byte) 0xFE, (byte) 0xC1, (byte) 0xD0, (byte) 0x8D, (byte) 0xF3, (byte) 0x02, (byte) 0x9C, (byte) 0xB7, (byte) 0xCE, (byte) 0xD9, (byte) 0x68, (byte) 0x28, (byte) 0x3A, (byte) 0x08, (byte) 0x4B, (byte) 0x7E, (byte) 0x38 };
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
		
		//{1: 2, -1: 1, -2: h'E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4', -3: h'F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941', -4: h'469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578'}
		public static byte[] data = new byte[] { (byte) 0xA5, (byte) 0x01, (byte) 0x02, (byte) 0x20, (byte) 0x01, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0xE2, (byte) 0xA7, (byte) 0xDC, (byte) 0x0C, (byte) 0x5D, (byte) 0x23, (byte) 0x83, (byte) 0x1A, (byte) 0x4F, (byte) 0x52, (byte) 0xFB, (byte) 0xFF, (byte) 0x75, (byte) 0x9E, (byte) 0xF0, (byte) 0x1A, (byte) 0x6B, (byte) 0x3A, (byte) 0x7D, (byte) 0x58, (byte) 0x69, (byte) 0x47, (byte) 0x74, (byte) 0xD6, (byte) 0xE8, (byte) 0x50, (byte) 0x5B, (byte) 0x31, (byte) 0xA3, (byte) 0x51, (byte) 0xD6, (byte) 0xC4, (byte) 0x22, (byte) 0x58, (byte) 0x20, (byte) 0xF8, (byte) 0xCA, (byte) 0x44, (byte) 0xFE, (byte) 0xDC, (byte) 0x6C, (byte) 0x32, (byte) 0x2D, (byte) 0x09, (byte) 0x46, (byte) 0xFC, (byte) 0x69, (byte) 0xAE, (byte) 0x74, (byte) 0x82, (byte) 0xCD, (byte) 0x06, (byte) 0x6A, (byte) 0xD1, (byte) 0x1F, (byte) 0x34, (byte) 0xAA, (byte) 0x5F, (byte) 0x5C, (byte) 0x63, (byte) 0xF4, (byte) 0xEA, (byte) 0xDB, (byte) 0x32, (byte) 0x0F, (byte) 0xD9, (byte) 0x41, (byte) 0x23, (byte) 0x58, (byte) 0x20, (byte) 0x46, (byte) 0x9C, (byte) 0x76, (byte) 0xF2, (byte) 0x6B, (byte) 0x8D, (byte) 0x9F, (byte) 0x28, (byte) 0x64, (byte) 0x49, (byte) 0xF4, (byte) 0x25, (byte) 0x66, (byte) 0xAB, (byte) 0x8B, (byte) 0x8B, (byte) 0xA1, (byte) 0xB3, (byte) 0xA8, (byte) 0xDC, (byte) 0x6E, (byte) 0x71, (byte) 0x1A, (byte) 0x1E, (byte) 0x2A, (byte) 0x6B, (byte) 0x54, (byte) 0x8D, (byte) 0xBE, (byte) 0x2A, (byte) 0x15, (byte) 0x78 };
		public static CBORObject public_key_cbor = CBORObject.DecodeFromBytes(data);
	}
	
	//Peter (does not support ECDSA)
	/*
	public static class Peter {
		final static byte client_rid[] = new byte[] { (byte) 0xC1 };		
		final static byte server_1_rid[] = new byte[] { (byte) 0xC2 };
		final static byte server_2_rid[] = new byte[] { (byte) 0xC3 };
		
		public static byte[] data = new byte[] { (byte) 0xA3, (byte) 0x01, (byte) 0x01, (byte) 0x20, (byte) 0x06, (byte) 0x21, (byte) 0x58, (byte) 0x20, (byte) 0x50, (byte) 0x8A, (byte) 0xFC, (byte) 0x1C, (byte) 0x29, (byte) 0x03, (byte) 0x7E, (byte) 0xF3, (byte) 0x61, (byte) 0x4D, (byte) 0x63, (byte) 0xAF, (byte) 0x87, (byte) 0xE1, (byte) 0xEA, (byte) 0x31, (byte) 0xD8, (byte) 0x91, (byte) 0xD7, (byte) 0x6B, (byte) 0x1F, (byte) 0x90, (byte) 0x60, (byte) 0x98, (byte) 0xAF, (byte) 0x8F, (byte) 0xA3, (byte) 0x9B, (byte) 0xBE, (byte) 0x87, (byte) 0x40, (byte) 0x19 };
		public static CBORObject public_key_cbor = CBORObject.DecodeFromBytes(data);
	}
	*/


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
		
		//recipientInfo.put(new ByteId(Peter.client_rid), Peter.public_key_cbor);
		//recipientInfo.put(new ByteId(Peter.server_1_rid), Peter.public_key_cbor);
		//recipientInfo.put(new ByteId(Peter.server_2_rid), Peter.public_key_cbor);
	}
	/* End Methods dealing with stored information about recipient IDs and associated keys */

}
