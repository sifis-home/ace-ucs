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

import se.sics.ace.AceException;

/**
 * This class implements scope validation for RESTful resources as follows:
 * 
 * Each statement in the scope is a "mini-ACL" concatenating the RESTful action(s)
 * (encoded as g = GET, p = POST, u = PUT, d = DELETE), and underscore '_' 
 * and the resource-uri.
 * 
 * For example gpu_tempC  would allow GET, PUT, POST (but not DELETE) on the 
 * resource 'tempC'
 * 
 * 
 * @author Ludwig Seitz
 *
 */
public class RESTscope implements ScopeValidator {

	@Override
	public boolean scopeMatchResource(String scope, String resourceId) 
			throws AceException {
		String parts[] = scope.split("_");
		if (parts.length != 2) {
			throw new AceException("Scope format not recognized");
		}
		return resourceId.equals(parts[1]);
	}

	@Override
	public boolean scopeMatch(String scope, String resource, String actionId) 
			throws AceException {
	    return scope.equals(actionId + "_" + resource);
	}
	
	/**
	 * Returns the <code>String</code> representing a coap Request code.
	 * 
	 * @param coapCode  the CoAP request code
	 * 
	 * @return  the action string for the scope
	 * 
	 * @throws AceException  thrown if the request code is unknown
	 */
	public static String fromCoap(int coapCode) throws AceException {
		switch (coapCode) {
			case 1: return "g";
			case 2: return "p";
			case 3: return "u";
			case 4: return "d";
			default: throw new AceException(
					"Unknwon CoAP request code " + coapCode);
		}
	}
}
