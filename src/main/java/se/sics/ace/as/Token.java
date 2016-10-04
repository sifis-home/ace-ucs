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

import se.sics.ace.Endpoint;
import se.sics.ace.Message;
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
	private Registrar rsInfo;
	
	@Override
	public Message processMessage(Message msg, CwtCryptoCtx ctx) 
				throws TokenException, PDPException {
		//1. Check if this client can request tokens
		if (!this.pdp.canAccessToken(msg.getSenderId())) {
			return msg.failReply(Message.FAIL_UNAUTHORIZED, null);
		}
		
		//2. Check if this client can request this type of token
		String allowedScopes = this.pdp.canAccess(msg.getSenderId(), 
				msg.getParameter("aud"), msg.getParameter("scope"));
		
		if (allowedScopes == null) {		
			return msg.failReply(Message.FAIL_FORBIDDEN, null);
		}
		
		//3. Check if this client and the RS support a common profile
		String profile = msg.getParameter("profile");
		if (profile != null) {
				if (!this.rsInfo.isProfileSupported(
						msg.getParameter("aud"), profile)) {
					return msg.failReply(Message.FAIL_NOT_ACCEPTABLE, null);
				}
			
		}
		
		//4. Create token
		//FIXME: Include scope in response parameters if different from the requested.
		
		return null; //FIXME: return something meaningful
	}

}
