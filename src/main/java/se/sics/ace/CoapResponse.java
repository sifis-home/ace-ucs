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
package se.sics.ace;


import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;

import com.upokecenter.cbor.CBORObject;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapResponse extends Response implements Message {
    
    /**
     * The parameters in the payload of this message as a Map for convenience.
     * This is null if the payload is empty or not a CBOR Map.
     */
    private Map<String, CBORObject> parameters = null;
    
    
    /**
     * Constructor
     * 
     * @param code  the response code
     * @param payload  the response payload, may be null
     * @param request   the request this responds to
     */
    public CoapResponse(ResponseCode code, CBORObject payload) {
        super(code);
        super.setPayload(payload.EncodeToBytes());   
    }

    /**
     * Constructor
     * 
     * @param code  the response code
     * @param parameters  the response parameters
     * @param request   the request this responds to
     */
    public CoapResponse(ResponseCode code, Map<String, CBORObject> parameters) {
        super(code);
        this.parameters.putAll(parameters);
        CBORObject map = CBORObject.NewMap();
        for (String key : this.parameters.keySet()) {
            short i = Constants.getAbbrev(key);
            if (i != -1) {
                map.Add(CBORObject.FromObject(i), this.parameters.get(key));
            } else { //This claim/parameter has no abbreviation
                map.Add(CBORObject.FromObject(key), this.parameters.get(key));
            }
        }
        super.setPayload(map.EncodeToBytes());   
    }
    
    @Override
    public byte[] getRawPayload() {
        return super.getPayload();
    }

    @Override
    public String getSenderId() {
        return null;
    }

    @Override
    public Set<String> getParameterNames() {
        if (this.parameters != null) {
            return this.parameters.keySet();
        }
        return null;
    }

    @Override
    public CBORObject getParameter(String name) {
        if (this.parameters != null) {
            return this.parameters.get(name);
        }
        return null;
    }

    @Override
    public Map<String, CBORObject> getParameters() {
        if (this.parameters != null) {
            Map<String, CBORObject> map = new HashMap<>();
            map.putAll(this.parameters);
            return map;
        }
        return null;
    }

    @Override
    public Message successReply(int code, CBORObject payload) {
        return null; //We don't generate a response to a response
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        return null; //We don't generate a response to a response
    }

    @Override
    public int getMessageCode() {
        return getCode().value;
    }

}
