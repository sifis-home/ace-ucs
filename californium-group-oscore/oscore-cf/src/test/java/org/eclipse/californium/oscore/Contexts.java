package org.eclipse.californium.oscore;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

public class Contexts {
	
	//General parameters
	
	final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	final static int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	//static final int TEMP = KeyKeys.EC2_P256.AsInt32();
	final static int replay_size = 32;
	
	//Common Context
	public static class Common {
	
		final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
		final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
				(byte) 0x78, (byte) 0x63, (byte) 0x40 };
		final static byte[] id_context = new byte[] { 0x44, 0x61, 0x6c };
		
		final static AlgorithmID alg_countersign = AlgorithmID.EDDSA;
		final static Integer par_countersign = ED25519; //Ed25519
		
	}
	
	//Entity #1
	public static class Entity_1 {
	
		final static byte[] sid = new byte[] { 0x25 };
		final static String sid_private_key_string = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
		//static OneKey sid_private_key;
	
	}
	
	//Entity #2
	public static class Entity_2 {
		
		final static byte[] rid1 = new byte[] { 0x52 };
		final static String rid1_public_key_string = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
		//static OneKey rid1_public_key;
	
	}
	
	//Entity #3
	public static class Entity_3 {
		
		final static byte[] rid2 = new byte[] { 0x77 };
		final static String rid2_public_key_string = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
		//static OneKey rid2_public_key;
	
	}
}

/*
 * 
 *
 * Common Context:
Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
Master Salt: 0x9e7ca92223786340 (8 bytes)
Common IV: 0x0x2ca58fb85ff1b81c0b7181b85e (13 bytes)
ID Context: 0x37cbf3210017a2d3 (8 bytes)
Par Countersign: 0x26
Par Countersign Key: 0x822601
Entity #1
Sender ID: 0xa1 (0 byte)
Sender Key: 0xaf2a1300a5e95788b356336eeecd2b92 (16 bytes)
Sender Seq Number: 00
Sender IV: 0x2ca58fb85ff1b81c0b7181b85e (using Partial IV: 00)
Signing Key: {1: 2, -1: 1, -2: hâ€™E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4â€™, -3: hâ€™F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941â€™, -4: hâ€™469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578â€™}
 * 
 * 
 * */
 