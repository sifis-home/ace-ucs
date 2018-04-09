/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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

import java.util.Map;

import org.eclipse.californium.core.coap.CoAP.Code;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.rs.ScopeValidator;

/**
 * This implements the scope format proposed in draft-bormann-core-ace-aif
 * 
 * FIXME: WORK IN PROGRESS
 * 
 * @author Ludwig Seitz
 *
 */
public class Aif implements ScopeValidator {

    /**
     * Representation of GET in the AIF
     */
    public static short GET = 2^0;
    
    /**
     *  Representation of POST in the AIF
     */
    public static short POST = 2^1;
    
    /**
     *  Representation of PUT in the AIF
     */
    public static short PUT = 2^2;
    
    /**
     *  Representation of DELETE in the AIF
     */
    public static short DELETE = 2^3;
    
    /**
     * 
     */
    public Aif() {
        
    }
    
    @Override
    public boolean scopeMatch(Object scope, String resourceId, String actionId)
            throws AceException {
        short actionIdS= 0; //FIXME
        
        if (!(scope instanceof byte[])) {  
            throw new AceException("Invalid scope format");
        }
        
        CBORObject scopeCB = CBORObject.DecodeFromBytes((byte[]) scope);
        if (!scopeCB.getType().equals(CBORType.Array)) {
            throw new AceException("Invalid scope format");
        }

        for (int i=0; i<scopeCB.size();i++) {
            CBORObject scopeElement = scopeCB.get(i);
            if (!scopeElement.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format");
            }
            String resource = scopeElement.get(0).AsString();
            short action = scopeElement.get(1).AsInt16();
            if (resource.equals(resourceId)) {
                //Check action
                if ((action & actionIdS) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean scopeMatchResource(Object scope, String resourceId)
            throws AceException {
        // TODO Auto-generated method stub
        return false;
    }

}
