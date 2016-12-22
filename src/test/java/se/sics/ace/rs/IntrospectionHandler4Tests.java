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

import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.as.Introspect;
import se.sics.ace.as.Message4Tests;

/**
 * An introspection handler that directly uses a se.sics.as.Introspect instance
 * for testing purposes.
 * 
 * @author Ludwig Seitz
 *
 */
public class IntrospectionHandler4Tests implements IntrospectionHandler {

    private Introspect i;
    
    private String rsId;
    
    private String asId; 
    
    /**
     * Create a new test introspection handler
     * 
     * @param i  the introspect library
     * @param rsId  the resource server's identifier
     * @param asId  the AS identifier
     */
    public IntrospectionHandler4Tests(Introspect i, String rsId, String asId) {
        this.i = i;
        this.rsId = rsId;
        this.asId = asId;
    }
  
    
    @Override
    public Map<String, CBORObject> getParams(String tokenReference) {
        Map<String, CBORObject> params = new HashMap<>();
        params.put("token", 
                CBORObject.FromObject(tokenReference));
        params.put("token_type_hint", 
                CBORObject.FromObject("pop"));
        Message4Tests req = new Message4Tests(0, this.rsId, this.asId, params);
        Message4Tests res = (Message4Tests)this.i.processMessage(req);
        return res.getParameters();
    }

}
