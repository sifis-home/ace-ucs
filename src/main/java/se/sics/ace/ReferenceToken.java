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
package se.sics.ace;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.rs.IntrospectionHandler;

/**
 * This class implements a reference token.
 * 
 * @author Ludwig Seitz
 *
 */
public class ReferenceToken implements AccessToken {

	/**
	 * The reference 
	 */
	private String ref;
	
	/**
	 * A handler for introspecting this token.
	 */
	private IntrospectionHandler introspect;
	
	/**
	 * Constructor.
	 * 
	 * @param length  the length in bits of the reference.
	 */
	public ReferenceToken(int length) {
		SecureRandom random = new SecureRandom();
		this.ref = new BigInteger(length, random).toString(32);
	}
	
	/**
	 * Constructor. Uses the default
	 * length of 128 bits for the reference.
	 */
	public ReferenceToken() {
		SecureRandom random = new SecureRandom();
		this.ref = new BigInteger(128, random).toString(32);
	}
	
	
	/**
	 * Add an introspection handler to this ReferenceToken in order to do 
	 * introspection.
	 * 
	 * @param intropsect
	 */
	public void addIntrospectionHandler(IntrospectionHandler intropsect) {
		this.introspect = intropsect;
	}
	
	@Override
	public boolean expired(long now) throws TokenException {
		if (this.introspect == null) {
			throw new TokenException("Need IntrospectionHandler");
		}
		Map<String, CBORObject> params = this.introspect.getParams(this.ref);
		CBORObject expO = params.get("exp");
		if (expO != null && expO.AsInt64() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}

	@Override
	public boolean isValid(long now) throws TokenException {
		if (this.introspect == null) {
			throw new TokenException("Need IntrospectionHandler");
		}
		Map<String, CBORObject> params = this.introspect.getParams(this.ref);
		//Check nbf and exp for the found match
				CBORObject nbfO = params.get("nbf");
				if (nbfO != null &&  nbfO.AsInt64()	> now) {
					return false;
				}	
				CBORObject expO = params.get("exp");
				if (expO != null && expO.AsInt64() < now) {
					//Token has expired
					return false;
				}
		return false;
	}

	@Override
	public CBORObject encode() {
		return CBORObject.FromObject(this.ref);
	}

}
