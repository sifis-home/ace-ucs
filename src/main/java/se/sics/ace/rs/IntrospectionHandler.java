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
 * An interface for classes handling introspection of tokens.
 * 
 * @author Ludwig Seitz
 *
 */
public interface IntrospectionHandler {

	/**
	 * Get the parameters (claims) for a token reference (probably through introspection).
	 * 
	 * @param tokenReference  the token reference
	 * 
	 * @return  the map of claims (key to claim value)
	 * @throws RSException 
	 */
	public Map<String, CBORObject> getParams(String tokenReference) 
				throws RSException;
	
}
