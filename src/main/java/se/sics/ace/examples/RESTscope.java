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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.rs.ScopeValidator;

/**
 * This class implements scope validation for RESTful resources as follows:
 * 
 * Each statement in the scope is a capability, in a format inspired by 
 * draft-bormann-core-ace-aif.
 * 
 *    o The entries in the table that specify the same local-part
 *      (Uri-Path & Uri-Query in CoAP) are merged into a single entry
 *       that specifies the union of the permission sets
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
	public boolean scopeMatchResource(Object scope, String resourceId) 
			throws AceException {
	    if (!(scope instanceof byte[])) {
	        throw new AceException("Scope must be a byte array");
	    }
	    CBORObject scp = CBORObject.DecodeFromBytes((byte[]) scope);
	    if (!scp.getType().equals(CBORType.Array)) {
	        throw new AceException("Scope must decode to CBOR array");
	    }
	    
	    for (int i = 0; i < scp.size();i++) {
	        CBORObject authz = scp.get(i);
	        if (!authz.getType().equals(CBORType.Array)) {
	            throw new AceException("Authorization must be CBOR array");
	        }
	        if (authz.size() != 2) {
	            throw new AceException("Malformed Authorization element");
	        }
	        CBORObject path = authz.get(0);
	        if (!path.getType().equals(CBORType.TextString)) {
	            throw new AceException("Path must be text string");
	        }
	        if (path.AsString().equals(resourceId)) {
	            //XXX: URI-Query would make this different
	            return true;
	        }
	        
	    }
		return false;
	}

	@Override
	public boolean scopeMatch(Object scope, String resource, String actionId) 
			throws AceException {
	    if (!(scope instanceof byte[])) {
            throw new AceException(
                    "RESTscope expects scopes to be byte array");
        }
	    CBORObject scp = CBORObject.DecodeFromBytes((byte[]) scope);
        if (!scp.getType().equals(CBORType.Array)) {
            throw new AceException("Scope must decode to CBOR array");
        }
        
        for (int i = 0; i < scp.size();i++) {
            CBORObject authz = scp.get(i);
            if (!authz.getType().equals(CBORType.Array)) {
                throw new AceException("Authorization must be CBOR array");
            }
            if (authz.size() != 2) {
                throw new AceException("Malformed Authorization element");
            }
            CBORObject path = authz.get(0);
            if (!path.getType().equals(CBORType.TextString)) {
                throw new AceException("Path must be text string");
            }
            CBORObject permission = authz.get(1);
            if (!permission.getType().equals(CBORType.Number)) {
                throw new AceException("Permission must be a number");
            }
                        
            if (path.AsString().equals(resource)) {
                short action = (short) (1 << (actionTranslator(actionId)-1));
                if ((action & permission.AsInt16()) != 0) {
                    return true;
                }
                //There should not be more than one authorization with 
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
	public CBORObject generateScope(String resourceUri, Code[] permission) {
	    int finalPermission = 0;
	    for (int i=0; i<permission.length; i++) {
	        int number = 1 << (permission[i].value-1);
	        finalPermission |= number;
	    }
	    CBORObject authz = CBORObject.NewArray();
	    authz.Add(resourceUri);
	    authz.Add(finalPermission);
	    return authz;
	}
	
	/**
	 * Translates an action String to the corresponding CoAP number.
	 * @param action
	 * @return  the action number from RFC7252
	 * @throws AceException 
	 */
	public short actionTranslator(String action) throws AceException {
	    if (action.equalsIgnoreCase("GET")) {
	        return 1;
	    } else if (action.equalsIgnoreCase("POST")) {
	        return 2;
	    } else if (action.equalsIgnoreCase("PUT")) {
	        return 3;
	    } else if (action.equalsIgnoreCase("DELETE")) {
	        return 4;
	    } else if (action.equalsIgnoreCase("FETCH")) {
	        return 5;
	    } else if (action.equalsIgnoreCase("PATCH")) {
            return 6;
        } else if (action.equalsIgnoreCase("iPATCH")) {
            return 7;
        }
	    throw new AceException("Unknown CoAP action name: " + action);
	}
}
