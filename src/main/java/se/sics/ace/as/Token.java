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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import se.sics.ace.AccessToken;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.TokenException;
import se.sics.ace.cwt.CWT;
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
	 * The counter for generating the cti
	 */
	private Long cti = 0L;
	
	/**
	 * The private key of the AS or null if there isn't any
	 */
	private CBORObject privateKey;
	
	/**
	 * The signature algorithm used by this AS if any or null
	 */
	private CBORObject sig0Alg;
	
	/**
	 * Constructor.
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param registrar  the registrar for registering clients and RSs
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * @param sig0Alg  the signature algorithm used with the asymmetric key pair
	 *     or null if asymmetric signatures are not used
	 */
	public Token(String asId, PDP pdp, Registrar registrar, 
	        TimeProvider time, CBORObject privateKey, CBORObject sig0Alg) {
	    this.asId = asId;
	    this.pdp = pdp;
	    this.registrar = registrar;
	}
	
	@Override
	public Message processMessage(Message msg) 
	        throws ASException, NoSuchAlgorithmException, 
	        IllegalStateException, InvalidCipherTextException, 
	        CoseException, TokenException {
		//1. Check if this client can request tokens
		String id = msg.getSenderId();
		if (!this.pdp.canAccessToken(id)) {
			return msg.failReply(Message.FAIL_UNAUTHORIZED, null);
		}
		
		//2. Check if this client can request this type of token
		String scope = msg.getParameter("scope").AsString();
		if (scope == null) {
			scope = this.registrar.getDefaultScope(id);
			if (scope == null) {
				return msg.failReply(Message.FAIL_BAD_REQUEST, 
						CBORObject.FromObject("request lacks scope"));
			}
		}
		String aud = msg.getParameter("aud").AsString();
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
		long exp = this.registrar.getExpiration(aud);
		if (exp == 0) {
		    exp = expiration;
		}
		claims.put("exp", CBORObject.FromObject(exp));
		claims.put("iat", CBORObject.FromObject(now));
		byte[] cti = Long.toHexString(this.cti).getBytes();
		this.cti++;
		claims.put("cti", CBORObject.FromObject(cti));
		claims.put("scope", CBORObject.FromObject(scope));

		//Find supported profile
		String profile = this.registrar.getSupportedProfile(id, aud);

		if (tokenType != AccessTokenFactory.CWT_TYPE &&
		        tokenType != AccessTokenFactory.REF_TYPE) {
		    return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, 
		            CBORObject.FromObject("Unsupported token type"));
		}
		
		//Find supported key type for proof-of-possession
		String keyType = this.registrar.getSupportedKeyType(id, aud);
		switch (keyType) {
		case "PSK":
		    KeyGenerator kg = KeyGenerator.getInstance("AES");
		    SecretKey key = kg.generateKey();
		    CBORObject psk = CBORObject.FromObject(key.getEncoded());
		    claims.put("cnf", psk);
		    break;
		case "RPK":
		    CBORObject rpk = msg.getParameter("cnf");
		    if (rpk == null) {
		        return msg.failReply(Message.FAIL_BAD_REQUEST, 
		                CBORObject.FromObject("Client needs to provide RPK"));
		    }
		    claims.put("cnf", rpk);
		    break;
		default :
		    return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, 
                    CBORObject.FromObject("Unsupported key type"));
		}
		
		AccessToken token = AccessTokenFactory.generateToken(tokenType, claims);

		CBORObject rsInfo = CBORObject.NewMap();
		rsInfo.Add(Constants.PROFILE, CBORObject.FromObject(profile));
		rsInfo.Add(Constants.CNF, claims.get("cnf"));
		if (token instanceof CWT) {
		    //Get CwtCryptoCtxs for the audience ...
		    CwtCryptoCtx ctx = this.registrar.getCommonCwtCtx(
		            aud, this.privateKey, this.sig0Alg);
		    if (ctx == null) {
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
		                CBORObject.FromObject(
		                "No common security context found for audience"));
		    }
		    CWT cwt = (CWT)token;
		    rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx));
		} else {
		    rsInfo.Add(Constants.ACCESS_TOKEN, token.encode());
		}
		
		
		return msg.successReply(Message.CREATED, rsInfo);
	}

}
