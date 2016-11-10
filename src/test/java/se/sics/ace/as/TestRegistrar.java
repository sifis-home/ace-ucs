/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
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
package se.sics.ace.as;
	
	import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Collections;
	import java.util.HashSet;
import java.util.Scanner;

import org.junit.Rule;
	import org.junit.Test;
	import org.junit.rules.ExpectedException;

import COSE.AlgorithmID;
import COSE.MessageTag;
import se.sics.ace.COSEparams;
	
	/**
	 * Test the AS code.
	 * 
	 * @author Ludwig Seitz
	 *
	 */
	public class TestRegistrar {
	
	    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	    
		/**
		 * Tests for AS.
		 */
		public TestRegistrar() {
		}
	
	
		/**
		 * 
		 */
		@Rule
		public ExpectedException thrown = ExpectedException.none();
	
		/**
		 * Test parsing an example configuration of the Registrar
		 * @throws Exception 
		 */
		@Test
		public void testParseConfig() throws Exception {
			Registrar r = new Registrar("src/test/resources/ASregistry.json");
			HashSet<String> keys = new HashSet<>();
			keys.add("PSK");
			r.addClient("clientC", Collections.singleton("coap_dtls"), "temp",
			        null, keys, key128, null);
			keys.add("RPK");
			HashSet<String> profiles = new HashSet<>();
			profiles.add("coap_dtls");
			profiles.add("coap_oscoap");
			HashSet<String> scopes = new HashSet<>();
			scopes.add("temp");
			scopes.add("co2");
			HashSet<String> auds = new HashSet<>();
			auds.add("sensors");
			auds.add("actuators");
			HashSet<Integer> tokens = new HashSet<>();
			COSEparams cose = new COSEparams(MessageTag.Sign1, 
			        AlgorithmID.ECDSA_256, AlgorithmID.Direct);
			tokens.add(AccessTokenFactory.CWT_TYPE);
			r.addRS("rs4", profiles, scopes, auds, keys, tokens, 
			        cose, 1000, key128, null);
			
			assert(r.getPopKeyType("clientC", "rs4").equals("PSK"));
			assert(r.getSupportedProfile("clientC", "rs4").equals("coap_dtls"));
			assert(r.getRS("sensors").contains("rs4"));
			assert(r.getRS("actuators").contains("rs4"));
			assert(Arrays.equals(key128, r.getSecretKey("rs4")));
			assert(r.getSupportedCoseType("rs4") == MessageTag.Sign1);
			assert(r.getSupportedTokenType("rs4").equals(AccessTokenFactory.CWT_TYPE));
			System.out.println(r.toString());
			r.remove("clientC");
			r.remove("rs4");
			FileInputStream fis = new FileInputStream(
			        "src/test/resources/ASregistry.json");
			Scanner scanner = new Scanner(fis, "UTF-8" );
			Scanner s = scanner.useDelimiter("\\A");
			String configStr = s.hasNext() ? s.next() : "";
			fis.close();
			scanner.close();
			s.close();
			fis = new FileInputStream(
			        "src/test/resources/ASregistry.json.bak");
			scanner = new Scanner(fis, "UTF-8");
			s = scanner.useDelimiter("\\A");
			String configBak = s.hasNext() ? s.next() : "";
			fis.close();
			scanner.close();
			s.close();
			assert(r.getPopKeyType("clientB", "actuators").equals("PSK"));
			assert(r.getPopKeyType("clientB", "sensors") == null);
			
			assert(r.getSupportedProfile("clientA", "sensors").equals("coap_dtls"));
			assert(r.getSupportedProfile("clientB", "sensors")== null);
		
			assert(r.getSupportedTokenType("actuators").equals(AccessTokenFactory.REF_TYPE));
			assert(r.getSupportedTokenType("sensors").equals(AccessTokenFactory.CWT_TYPE));
			
			assert(configStr.equals(configBak));
		}
	}
	
	
	
