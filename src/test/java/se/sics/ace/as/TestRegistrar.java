/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
package se.sics.ace.as;
	
	import java.io.FileInputStream;
import java.util.Collections;
	import java.util.HashSet;
import java.util.Scanner;

import org.junit.Rule;
	import org.junit.Test;
	import org.junit.rules.ExpectedException;
	
	/**
	 * Test the AS code.
	 * 
	 * @author Ludwig Seitz
	 *
	 */
	public class TestRegistrar {
	
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
			keys.add("RPK");
			r.addClient("client_C", Collections.singleton("coap_dtls"), "temp", null, keys);
			r.remove("client_C");
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
			tokens.add(AccessTokenFactory.CWT_TYPE);
			r.addRS("rs4", profiles, scopes, auds, keys, tokens);
			r.remove("rs4");
			FileInputStream fis = new FileInputStream("src/test/resources/ASregistry.json");
			Scanner scanner = new Scanner(fis, "UTF-8" );
			Scanner s = scanner.useDelimiter("\\A");
			String configStr = s.hasNext() ? s.next() : "";
			fis.close();
			scanner.close();
			s.close();
			fis = new FileInputStream("src/test/resources/ASregistry.json.bak");
			scanner = new Scanner(fis, "UTF-8");
			s = scanner.useDelimiter("\\A");
			String configBak = s.hasNext() ? s.next() : "";
			fis.close();
			scanner.close();
			s.close();
			assert(configStr.equals(configBak));
			
		}
	}
	
	
	
