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

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

/**
 * A protocol message for either /token, /introspect or /authz-info.
 * This abstract class is meant to be protocol independent, classes that implement
 * concrete instances could e.g. represent a CoAP message. 
 * Messages are expected to have a Map of parameters (which may be empty).
 * 
 * @author Ludwig Seitz
 *
 */
public abstract class Message {
	
    /**
     * Generic success code
     */
    public static int OK = 200;
    
    /**
     * Request has been fulfilled, resulting in the creation of a new resource.
     */
    public static int CREATED = 201;
    
	/**
	 * Generic failure reasons code (following REST/HTTP/COAP).
	 */
	public static int FAIL_BAD_REQUEST = 400;
	
	/**
	 * Request was not authorized, the requester should try to authenticate
	 */
	public static int FAIL_UNAUTHORIZED = 401;
	
	/**
	 * Requester lacks permission to perform this request
	 */
	public static int FAIL_FORBIDDEN = 403;
	
	/**
	 * Requested resource was not found
	 */
	public static int FAIL_NOT_FOUND = 404;
	
	/**
	 * The requested operation on the resource is not allowed for this
	 * 	requester
	 */ 
	public static int FAIL_METHOD_NOT_ALLOWED = 405;
	
	/**
	 * The responder cannot generate acceptable data format in the response
	 */
	public static int FAIL_NOT_ACCEPTABLE = 406;
	
	/**
	 * The request contained payload in a unsupported data format
	 */
	public static int FAIL_UNSUPPORTED_CONTENT_FORMAT = 415;
	
	/**
	 * The server had some internal problem
	 */
	public static int FAIL_INTERNAL_SERVER_ERROR = 500;
	
	/**
	 * The server doesn't implement some part required for this request
	 */
	public static int FAIL_NOT_IMPLEMENTED = 501;
	
	/**
	 * The raw byte[] value of the payload of this message.
	 */
	private byte[] rawPayload;
	
	/**
	 * The identifier of the sender of this message.
	 */
	private String senderId; 
	
	/**
	 * Parameters of this message
	 */
	private Map<String, CBORObject> parameters = Collections.emptyMap();
	
	
	/**
	 * @return  the raw bytes of the payload
	 */
	public byte[] getRawPayload() {
		return this.rawPayload;
	}
	
	/**
	 * @return  The senders identity. This is assumed to have been authenticated by a lower
	 * 	level protocol.
	 */
	public String getSenderId() {
		return this.senderId;
	}
	
	/**
	 * @return  a set of the parameter names, may be empty.
	 */
	public Set<String> getParameterNames() {
		return this.parameters.keySet();
	}
	
	/**
     * Returns a parameter, or null if the parameter does not exist
     * 
	 * @param name  the name of the parameter
	 * @return  the parameter value or null if it doesn't exist
	 */
	public CBORObject getParameter(String name) {
		return this.parameters.get(name);
	}
	
	/**
	 * @return  the <code>Map</code> of parameters for this message.
	 */
	public Map<String, CBORObject> getParameters() {
		return this.parameters;
	}
	
	/**
	 * Generate a reply message indicating success.
	 * 
	 * @param code  the success code
	 * @param payload  the payload of the reply, can be null.
	 * 
	 * @return  the reply message
	 */
	public abstract Message successReply(int code, CBORObject payload);
	
	/**
	 * Generate a reply message indicating failure.
	 * 
	 * @param failureReason  the failure reason code.
	 * @param payload  the payload of the reply, can be null.
	 * 
	 * @return  the reply message
	 */
	public abstract Message failReply(int failureReason, CBORObject payload);

}
