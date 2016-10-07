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

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.TokenException;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * Note: If a client requests a scope that is not supported by (parts) of the audience
 * this endpoint will just ingore that, assuming that the client will be denied by the PDP anyway,
 * This requires a default deny policy in the PDP.
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
	 * The RS registration information this endpoint uses.
	 */
	private Registrar registrar;
	
	/**
	 * The token factory
	 */
	private AccessTokenFactory factory;
	
	/**
	 * The identifier of this AS for the iss claim.
	 */
	private String asId;
	
	/**
	 * The time provider for this AS.
	 */
	private TimeProvider time;
	
	/**
	 * The default expiration time of an access token
	 */
	private static long expiration = 1000 * 60 * 10; //10 minutes
	
	/**
	 * Constructor.
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param registrar  the registrar for registering clients and RSs
  	 * @param factory  the token factory 
	 * @param time  the time provider
	 */
	public Token(String asId, PDP pdp, Registrar registrar, 
	        AccessTokenFactory factory, TimeProvider time) {
	    this.asId = asId;
	    this.pdp = pdp;
	    this.registrar = registrar;
	    this.factory = factory;
	}
	
	@Override
	public Message processMessage(Message msg, CwtCryptoCtx ctx) 
				throws TokenException, ASException {
		//1. Check if this client can request tokens
		String id = msg.getSenderId();
		if (!this.pdp.canAccessToken(id)) {
			return msg.failReply(Message.FAIL_UNAUTHORIZED, null);
		}
		
		//2. Check if this client can request this type of token
		String scope = msg.getParameter("scope");
		if (scope == null) {
			scope = this.registrar.getDefaultScope(id);
			if (scope == null) {
				return msg.failReply(Message.FAIL_BAD_REQUEST, 
						CBORObject.FromObject("request lacks scope"));
			}
		}
		String aud = msg.getParameter("aud");
		if (aud == null) {
			aud = this.registrar.getDefaultAud(id);
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
		//Find supported token type
		int tokenType = this.registrar.getSupportedTokenType(aud);
		
		
		Map<String, CBORObject> claims = new HashMap<>();
		claims.put("iss", CBORObject.FromObject(this.asId));
		claims.put("aud", CBORObject.FromObject(aud));
		 claims.put("sub", CBORObject.FromObject(id));
		 long now = this.time.getCurrentTime();
		 //claims.put("exp", CBORObject.FromObject());
		 //claims.put("nbf", CBORObject.FromObject());
		 claims.put("iat", CBORObject.FromObject(new Date().getTime()));
		 byte[] cti = {0x0B, 0x71};
		 claims.put("cti", CBORObject.FromObject(cti));
		 claims.put("cnf", CBORObject.FromObject("FIXME")); //FIXME
		 claims.put("scope", CBORObject.FromObject(
		         "r+/s/light rwx+/a/led w+/dtls"));
		 
		 //Find supported profile
		//Find supported key type
		//
		//AccessToken token = this.factory.generateToken(type, claims);
		
		
		
		return null; //FIXME: return something meaningful
	}

}
