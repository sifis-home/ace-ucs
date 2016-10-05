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
package se.sics.ace.as;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TokenException;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * @author Ludwig Seitz
 *
 */
public class Token implements Endpoint {

	/**
	 * The PDP this endpoint uses to make access control decisions.
	 */
	private PDP pdp;
	
	/**
	 * The RS registeration information this endpoint uses.
	 */
	private Registrar registrar;
	
	@Override
	public Message processMessage(Message msg, CwtCryptoCtx ctx) 
				throws TokenException, PDPException {
		//1. Check if this client can request tokens
		String id = msg.getSenderId();
		if (!this.pdp.canAccessToken(id)) {
			return msg.failReply(Message.FAIL_UNAUTHORIZED, null);
		}
		
		//2. Check if this client can request this type of token
		String scope = msg.getParameter("scope");
		if (scope == null) {
			scope = registrar.getDefaultScope(id);
			if (scope == null) {
				return msg.failReply(Message.FAIL_BAD_REQUEST, 
						CBORObject.FromObject("request lacks scope"));
			}
		}
		String aud = msg.getParameter("aud");
		if (aud == null) {
			aud = registrar.getDefaultAud(id);
			if (aud == null) {
				return msg.failReply(Message.FAIL_BAD_REQUEST,
						CBORObject.FromObject("request lacks audience"));
			}
		}
		String allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
		
		if (allowedScopes == null) {		
			return msg.failReply(Message.FAIL_FORBIDDEN, null);
		}
		
		//4. Create token
		
		
		return null; //FIXME: return something meaningful
	}

}
