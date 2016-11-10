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
