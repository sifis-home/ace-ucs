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
package se.sics.ace.rs;

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

/**
 * An IntrospectionHandler that uses CoAP to talk to the /introspect endpoint at the AS.
 * 
 * @author Ludwig Seitz
 */
public class CoapIntrospection implements IntrospectionHandler {

	private String asAddress;
	
	/**
	 * Constructor.
	 * 
	 * @param asAddress  the base address of the AS
	 */
	public CoapIntrospection(String asAddress) {
		this.asAddress = asAddress;
	}
	
	
	@Override
	public Map<String, CBORObject> getParams(String tokenReference) {
		CBORObject requestParams = CBORObject.NewMap();
		requestParams.Add(CBORObject.FromObject("token"), 
				CBORObject.FromObject(tokenReference));
		requestParams.Add(CBORObject.FromObject("token_type_hint"), 
				CBORObject.FromObject("pop"));
		
		//FIXME: Generate CoAP request
		
		//FIXME: Retrieve CoAP response
		
		//FIXME: Return something meaningful
		return null;
	}

}
