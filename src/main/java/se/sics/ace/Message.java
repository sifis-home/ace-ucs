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
package se.sics.ace;

import com.upokecenter.cbor.CBORObject;

/**
 * A protocol message for either /token, /introspect or /authz-info.
 * Could e.g. be a CoAP message.
 * 
 * @author Ludwig Seitz
 *
 */
public abstract class Message {
	
	/**
	 * The raw byte[] value of the payload of this message.
	 */
	private byte[] rawPayload;
	
	/**
	 * The identifier of the sender of this message.
	 */
	private String senderId; 
	
	
	/**
	 * @return  the raw bytes of the payload
	 */
	public byte[] getRawPayload() {
		return this.rawPayload;
	}
	
	/**
	 * @return  The senders identity. This is assumed to have been authenticated by a lower
	 * 	level protocl.
	 */
	public String getSenderId() {
		return this.senderId;
	}
	
	
	/**
	 * Generate a reply message indicating success.
	 * 
	 * @param msg  the request message
	 * @param payload  the payload of the reply, can be null.
	 * 
	 * @return  the reply message
	 */
	public abstract Message successReply(Message msg, CBORObject payload);
	
	/**
	 * Generate a reply message indicating failure.
	 * 
	 * @param msg  the request message
	 * @param payload  the payload of the reply, can be null.
	 * 
	 * @return  the reply message
	 */
	public abstract Message failReply(Message msg, CBORObject payload);

}
