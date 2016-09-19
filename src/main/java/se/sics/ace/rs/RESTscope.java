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

/**
 * This class implements scope validation for RESTful resources as follows:
 * 
 * Each statement in the scope is a "mini-ACL" concatenating the RESTful action(s)
 * (encoded as g = GET, p = POST, u = PUT, d = DELETE), and underscore '_' 
 * and the resource-uri.
 * 
 * For example gpu_/tempC  would allow GET, PUT, POST (but not DELETE) on the 
 * resource '/tempC'
 * 
 * 
 * @author Ludwig Seitz
 *
 */
public class RESTscope implements ScopeValidator {

	@Override
	public boolean scopeIncludesResource(String scope, String resourceId) 
			throws RSException {
		String parts[] = scope.split("_");
		if (parts.length != 2) {
			throw new RSException("Scope format not recognized");
		}
		return resourceId.equals(parts[1]);
	}

	@Override
	public boolean scopeIncludesAction(String scope, String actionId) 
			throws RSException {
		String parts[] = scope.split("_");
		if (parts.length != 2) {
			throw new RSException("Scope format not recognized");
		}
		return parts[0].contains(actionId);
	}
	
	/**
	 * Returns the <code>String</code> representing a coap Request code.
	 * 
	 * @param coapCode  the CoAP request code
	 * 
	 * @return  the action string for the scope
	 * 
	 * @throws RSException  thrown if the request code is unknown
	 */
	public static String fromCoap(int coapCode) throws RSException {
		switch (coapCode) {
			case 1: return "g";
			case 2: return "p";
			case 3: return "u";
			case 4: return "d";
			default: throw new RSException(
					"Unknwon CoAP request code " + coapCode);
		}
	}
}
