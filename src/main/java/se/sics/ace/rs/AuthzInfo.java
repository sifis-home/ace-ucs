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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
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
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(AuthzInfo.class.getName());
    
    /**
     * The token storage
     */
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
		this.ctx = ctx;
	}

	@Override
	public Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    
		//1. Check whether it is a CWT or REF type
	    CBORObject cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    Map<String, CBORObject> claims = null;
	    if (cbor.getType().equals(CBORType.TextString)) {
	        try {
                claims = processRefrenceToken(msg);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted: " + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
	        CBORObject active = claims.get("active");
	        if (active.isFalse()) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Token is not active");
	            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	        }
	    } else if (cbor.getType().equals(CBORType.Array)) {
	        try {
	            claims = processCWT(msg);
	        } catch (Exception e) {
	            CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
                map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	        }
	    } else {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "invalid reuqest");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }

	    //2. Check that the token is not expired (exp)
	    CBORObject exp = claims.get("exp");
	    if (exp != null && exp.AsInt64() < this.time.getCurrentTime()) { 
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token is expired");
	        return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }   
      
	    //3. Check if we accept the issuer (iss)
	    CBORObject iss = claims.get("iss");
	    if (iss == null) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Token has no issuer");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token has no issuer");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    if (!this.issuers.contains(iss.AsString())) {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	        map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "Token issuer unknown");
	        return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }

	    //4. Check if we are the audience (aud)
	    CBORObject aud = claims.get("aud");
	    if (aud == null) {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "Token has no audience");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    if (!this.audience.match(aud.AsString())) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience does not apply");
	        return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }

	    //5. Check if the scope is meaningful to us
	    CBORObject scope = claims.get("scope");
	    if (scope == null) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token has no scope");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    try {
            if (!this.tr.inScope(scope.AsString())) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
                map.Add(Constants.ERROR_DESCRIPTION, "Scope does not apply");
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }


	    //6. Store the claims of this token
	    try {
            this.tr.addToken(claims, this.ctx);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

	    //9. Create success message
	    //XXX: Ok to return cti ? Might be null
	    return msg.successReply(Message.CREATED, claims.get("cti"));
	}
	
	/**
	 * Process a message containing a CWT.
	 * 
	 * @param msg  the message
	 * 
	 * @return  the claims of the CWT
	 * 
	 * @throws Exception
	 */
	private Map<String,CBORObject> processCWT(Message msg) throws Exception {
	    CWT cwt = CWT.processCOSE(msg.getRawPayload(), this.ctx);
        return cwt.getClaims();
    }
    
	/**
	 * Process a message containing a reference token.
	 * 
	 * @param msg  the message
	 * 
	 * @return  the claims of the reference token
	 * @throws AceException
	 */
    private Map<String, CBORObject> processRefrenceToken(Message msg)
                throws AceException {
        
        // This should be a CBOR String
        CBORObject token = CBORObject.DecodeFromBytes(msg.getRawPayload());
        if (token.getType() != CBORType.TextString) {
            throw new AceException("Reference Token processing error");
        }
        
        // Try to introspect the token
        Map<String, CBORObject> params 
            = this.intro.getParams(token.AsString());
        
        if (params == null) {
            params = new HashMap<>();
            params.put("active", CBORObject.False);
        }
       
        return params;
	}
    
    /**
     * Get the proof-of-possession key of a token identified by its 'cti'.
     * 
     * @param cti  the cti of the token
     * 
     * @return  the pop key or null if this cti is unknown
     * 
     * @throws AceException 
     */
    public OneKey getPoP(String cti) throws AceException {
        return this.tr.getPoP(cti);
    }

    @Override
    public void close() throws AceException {
        // Nothing to do.
        
    }	
}
