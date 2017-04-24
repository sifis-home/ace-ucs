/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
package se.sics.ace.examples;

import org.eclipse.californium.core.coap.CoAP.Code;

import se.sics.ace.AceException;
import se.sics.ace.rs.ScopeValidator;

/**
 * This class implements scope validation for RESTful resources as follows:
 * 
 * Each statement in the scope is a capability, in a format inspired by 
 * draft-bormann-core-ace-aif.
 * 
 *    o The entries in the table that specify the same local-part are
 *      merged into a single entry that specifies the union of the
 *      permission sets
 *
 *    o The methods in the permission sets are converted into their CoAP
 *      method numbers, minus 1
 *
 *    o The set of numbers is converted into a single number by taking
 *      each number to the power of two and computing the inclusive OR of
 *      the binary representations of all the numbers.
 *      
 *    o The final statement is the local-Uri concatenated with "|" concatenated with the
 *      number representing the permission set (note that "|" is a valid character for scopes
 *      but invalid in URI's, thus it is a safe separator)
 *
 * @author Ludwig Seitz
 *
 */
public class RESTscope implements ScopeValidator {
    
    /**
     * Constructor
     */
    public RESTscope() {
        //Nothing to do
    }

	@Override
	public boolean scopeMatchResource(String scope, String resourceId) 
			throws AceException {
		String[] subscope = scope.split(" ");
		for (int i=0; i<subscope.length; i++) {
		    String parts[] = subscope[i].split("\\|");
		    if (parts.length != 2) {
		        throw new AceException("Scope format not recognized");
		    }
		    if (resourceId.equals(parts[0])) {
		        return true;
		    }
		}
		return false;
	}

	@Override
	public boolean scopeMatch(String scope, String resource, String actionId) 
			throws AceException {
	    String[] subscope = scope.split(" ");
	    for (int i=0; i<subscope.length; i++) {
            String parts[] = subscope[i].split("\\|");
            if (parts.length != 2) {
                throw new AceException("Scope format not recognized");
            }
            if (resource.equals(parts[0])) {
               int action = 1 << (actionTranslator(actionId)-1);
               int permissions = Integer.parseInt(parts[1]);
               if ((permissions | action) == permissions) {
                   return true;
               } 
               //There should not be more than one subscope with 
               //the same resource Uri part so we can abort here
               return false;
            }
        }
        return false;
	}
	
	/**
	 * Calculate the scope substring for a resource and a set of permissions.
	 * 
	 * @param resourceUri  the resource Uri
	 * @param permission  the array of permissions (from 
	 *     <code>org.eclipse.californium.core.coap.CoAP.Code</code>)
	 *     
	 * @return  the final substring for the scope
	 */
	public String generateScope(String resourceUri, Code[] permission) {
	    int finalPermission = 0;
	    for (int i=0; i<permission.length; i++) {
	        int number = 1 << (permission[i].value-1);
	        finalPermission |= number;
	    }
	    return resourceUri + "|" + finalPermission;
	}
	
	/**
	 * Translates an action String to the corresponding CoAP number.
	 * @param action
	 * @return  the action number from RFC7252
	 * @throws AceException 
	 */
	public int actionTranslator(String action) throws AceException {
	    if (action.equalsIgnoreCase("GET")) {
	        return 1;
	    } else if (action.equalsIgnoreCase("POST")) {
	        return 2;
	    } else if (action.equalsIgnoreCase("PUT")) {
	        return 3;
	    } else if (action.equalsIgnoreCase("DELETE")) {
	        return 4;
	    }
	    throw new AceException("Unknown CoAP action name: " + action);
	}
}
