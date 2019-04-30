package se.sics.test;

//Rikard: Test class using both ACE and OSCORE
//Note: Test that updated CBOR version works for ACE
//Also fix so the build path is set automatically (include .classpath files? / or maven?)
//Fix this test application to have a different name

import java.util.HashMap;
import java.util.Map;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.*;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.oscore.GroupOSCORESecurityContextObject;

public class Tester {

	
	public static void main()
	{
	
		byte[] master_secret = null;
		AlgorithmID alg = null;
		byte[] sid = null;
		AlgorithmID kdf = null;
		OneKey sid_private_key = null;
		Integer par_countersign = null;
		AlgorithmID alg_countersign = null;
		byte[] group_identifier = null;
		byte[] master_salt = null;
		Integer value = new Integer(32);
	
		com.upokecenter.cbor.CBORObject test;
	
		Map<Short, Short> contextParams = new HashMap<>();
		Map<Short, CBORObject> contextParams2 = new HashMap<>();
	
		
		
		//ACE
		GroupOSCORESecurityContextObject test1 = new GroupOSCORESecurityContextObject(contextParams2);
		
		//Group OSCORE
		try {
		GroupOSCoreCtx ctx = new GroupOSCoreCtx(master_secret, true, alg, sid, kdf, value,
				master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
		} catch (Exception e) {
			System.out.println("a");
		}
		
		System.out.println("Hello");
	}

}
