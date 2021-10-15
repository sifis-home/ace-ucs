package se.sics.prototype.support;

//Rikard: Test class using both ACE and OSCORE
//Note: Test that updated CBOR version works for ACE
//Also fix so the build path is set automatically (include .classpath files? / or maven?)
//Fix this test application to have a different name

import java.util.HashMap;
import java.util.Map;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.*;
import org.eclipse.californium.oscore.group.GroupCtx;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.oscore.GroupOSCOREInputMaterialObject;

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
		GroupOSCOREInputMaterialObject test1 = new GroupOSCOREInputMaterialObject(contextParams2);
		
		//Group OSCORE
		GroupCtx groupOscoreCtx = null;
		try {
			groupOscoreCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier,
					alg_countersign, new byte[0]);
		} catch (Exception e) {
			System.out.println("a");
		}
		
		System.out.println("Hello " + groupOscoreCtx.toString());
	}

}
