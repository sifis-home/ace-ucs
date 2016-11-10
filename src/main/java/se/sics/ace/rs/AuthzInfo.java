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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.CoseException;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;


/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 *  
 * @author Ludwig Seitz
 *
 */
public class AuthzInfo implements Endpoint {
	
	private TokenRepository tr;
	
	/**
	 * The acceptable issuers
	 */
	private List<String> issuers;
	
	/**
	 * Provides system time
	 */
	private TimeProvider time;
	
	/**
	 * Handles introspection of tokens
	 */
	private IntrospectionHandler intro;
	
	/**
	 * Handles audience validation
	 */
	private AudienceValidator audience;
	
	/**
	 * The crypto context to use with the AS
	 */
	private CwtCryptoCtx ctx;
	
	
	/**
	 * Constructor.
	 * 
	 * @param tr  a token repository
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 */
	public AuthzInfo(TokenRepository tr, List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, CwtCryptoCtx ctx) {
		this.tr = tr;
		this.issuers = new ArrayList<>();
		this.issuers.addAll(issuers);
		this.time = time;
		this.intro = intro;
		this.audience = audience;
	}

	@Override
	public Message processMessage(Message msg) throws Exception {

		//1. Check if this is a CWT, and check the crypto wrapper
		CWT cwt = null;
		try {
			cwt = CWT.processCOSE(msg.getRawPayload(), this.ctx);
		} catch (CoseException ce) {
			//Not a CWT, check if this is a reference token
			return processRefrenceToken(msg);
		}

		//2. Check that the token is not expired (exp)
		if (cwt.expired(this.time.getCurrentTime())) {
			throw new RSException("Token has expired");
		}
		
		//3. Check if we accept the issuer (iss)
		CBORObject iss = cwt.getClaim("iss");
		if (iss == null) {
			throw new RSException("Token has no issuer");
		}
		if (!this.issuers.contains(iss.AsString())) {
			throw new RSException("Issuer " + iss + " not acceptable");
		}
		
		//4. Check if we are the audience (aud)
		CBORObject aud = cwt.getClaim("aud");
		if (aud == null) {
			throw new RSException("Token has no audience");
		}
		if (!this.audience.match(aud.AsString())) {
			throw new RSException("We are not the audience of this token");
		}
		
		//5. Check if the scope is meaningful to us
		CBORObject scope = cwt.getClaim("scope");
		if (scope == null) {
			throw new RSException("Token has no scope");
		}
		if (!this.tr.inScope(scope.AsString())) {
			throw new RSException("Token is not in scope");
		}
		
		//6. Store the claims of this token		
		this.tr.addCWT(cwt);
		
		//7. create success message
		return msg.successReply(Message.CREATED, null);
	}

	private Message processRefrenceToken(Message msg) throws RSException {
		//1. This should be a CBOR String
		CBORObject token = CBORObject.DecodeFromBytes(msg.getRawPayload());
		if (token.getType() != CBORType.TextString) {
			throw new RSException("Token reference is not a CBOR String");
		}
		
		//2. Try to introspect it
		Map<String, CBORObject> params = this.intro.getParams(token.AsString());
		
		//3. Check if the token is active
		CBORObject active = params.get("active");
		if (active == null) {
			throw new RSException("Missing 'active' parameter");
		}
		if (!active.AsBoolean()) {
			throw new RSException("Token is not active");
		}
		
		//4. Check that the token is not expired (exp)
		CBORObject exp = params.get("exp");
		if (exp != null && exp.AsInt64() > this.time.getCurrentTime()) { 
			throw new RSException("Token is expired");
		}	
		
		//5. Check if we accept the issuer (iss)
		CBORObject iss = params.get("iss");
		if (iss == null) {
			throw new RSException("Token has no issuer");
		}
		if (!this.issuers.contains(iss.AsString())) {
			throw new RSException("Issuer " + iss + " not acceptable");
		}
		
		//6. Check if we are the audience (aud)
		CBORObject aud = params.get("aud");
		if (aud == null) {
			throw new RSException("Token has no audience");
		}
		if (!this.audience.match(aud.AsString())) {
			throw new RSException("We are not the audience of this token");
		}
		
		//7. Check if the scope is meaningful to us
		CBORObject scope = params.get("scope");
		if (scope == null) {
			throw new RSException("Token has no scope");
		}
		if (!this.tr.inScope(scope.AsString())) {
			throw new RSException("Token is not in scope");
		}
		
		
		//8. Store the claims of this token
		this.tr.addRefToken(token.AsString(), params);
		
		//9. Create success message
		return msg.successReply(Message.CREATED, null);
	}	
}
