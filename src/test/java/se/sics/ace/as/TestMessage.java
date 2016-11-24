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
package se.sics.ace.as;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.Constants;
import se.sics.ace.Message;

/**
 * A testing class implementing a dummy message. 
 * 
 * @author Ludwig Seitz
 *
 */
public class TestMessage implements Message {

    /**
     * The authenticated id of the sender
     */
    private String senderId;
    
    /**
     * The parameters contained in the payload of this message
     */
    private Map<String, CBORObject> params;
    
    /**
     * The payload of the message when it is not a Map
     */
    private CBORObject payload;
    
    /**
     * The request or response code
     */
    private int code;
    
    /**
     * Constructor.
     * @param code 
     * @param senderId
     * @param parameters
     */
    public TestMessage(int code, String senderId, Map<String, CBORObject> parameters) {
        this.code = code;
        this.senderId = senderId;
        this.params = new HashMap<>();
        this.params.putAll(parameters);
        this.payload = null;
    }

    /**
     * Constructor.
     * @param code 
     * @param senderId
     * @param payload
     */
    public TestMessage(int code, String senderId,CBORObject payload) {
        this.code = code;
        this.senderId = senderId;
        this.params = null;
        this.payload = payload;
    }

    
    
    @Override
    public Message successReply(int code, CBORObject payload) {
        return new TestMessage(code, "TestRS", payload);
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        return new TestMessage(failureReason, "TestRS", payload);
    }


    @Override
    public byte[] getRawPayload() {
       return (this.payload == null) 
               ? null : this.payload.EncodeToBytes();
    }


    @Override
    public String getSenderId() {
        return this.senderId;
    }


    @Override
    public Set<String> getParameterNames() {
        return (this.params == null) 
                ? null : this.params.keySet();
    }


    @Override
    public CBORObject getParameter(String name) {
        return (this.params == null) 
                ? null : this.params.get(name);
    }


    @Override
    public Map<String, CBORObject> getParameters() {
        if (this.params == null) {
            return null;
        }
        HashMap<String, CBORObject> ret = new HashMap<>();
       ret.putAll(this.params);
       return ret;
    }

    @Override
    public int getMessageCode() {
        return this.code;
    }
    
    /**
     * Remaps a parameter map to the unabbreviated version.
     * 
     * @param map
     */
    public static void unabbreviate(CBORObject map) {
        if (!map.getType().equals(CBORType.Map)) {
            return;
        }
        Map<CBORObject, CBORObject> replacer = new HashMap<>();
        for (CBORObject key : map.getKeys()) {
            if (key.isIntegral()) {
                int keyInt = key.AsInt32();
                if (keyInt > 0 && keyInt < Constants.ABBREV.length) {
                    replacer.put(key, 
                            CBORObject.FromObject(Constants.ABBREV[keyInt]));
                    
                }
            }
        }
        for (CBORObject key : replacer.keySet()) {
            CBORObject value = map.get(key);
            map.Remove(key);
            map.Add(replacer.get(key), value);
        }
    }

}
