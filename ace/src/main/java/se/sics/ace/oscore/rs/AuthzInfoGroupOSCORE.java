/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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
package se.sics.ace.oscore.rs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.CoseException;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.ScopeValidator;
import se.sics.ace.rs.TokenRepository;


/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class AuthzInfoGroupOSCORE implements Endpoint, AutoCloseable {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(AuthzInfo.class.getName());

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
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param audience  the audience validator
	 * @param tokenFile  the file where to save tokens when persisting
     * @param scopeValidator  the application specific scope validator 
	 * @param ctx  the crypto context to use with the As
	 * @throws IOException  if TokenRepository creation fails
	 * @throws AceException if TokenRepository creation fails 
	 */
	public AuthzInfoGroupOSCORE(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, String tokenFile, 
			ScopeValidator scopeValidator, CwtCryptoCtx ctx) 
			        throws AceException, IOException {
	    if (TokenRepository.getInstance()==null) {	   
	        TokenRepository.create(scopeValidator, tokenFile, ctx, time);
	    }
		this.issuers = new ArrayList<>();
		this.issuers.addAll(issuers);
		this.time = time;
		this.intro = intro;
		this.audience = audience;
		this.ctx = ctx;
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject token = null;
	    try {
	        token = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    } catch (Exception e) {
	        LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }
	    
	    Map<Short, CBORObject> claims = null;

		//1. Check whether it is a CWT or REF type
	    if (token.getType().equals(CBORType.ByteString)) {
	        try {
                claims = processRefrenceToken(token);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted: " + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            } catch (IntrospectionException e) {
                LOGGER.info("Introspection error, "
                         + "message processing aborted: " + e.getMessage());
                if (e.getMessage().isEmpty()) {
                    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
                return msg.failReply(e.getCode(), map);
            }
	    } else if (token.getType().equals(CBORType.Array)) {
	        try {
	            claims = processCWT(token);
	        } catch (IntrospectionException e) {
                LOGGER.info("Introspection error, "
                        + "message processing aborted: " + e.getMessage());
               if (e.getMessage().isEmpty()) {
                   return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
               }
               CBORObject map = CBORObject.NewMap();
               map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
               map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
               return msg.failReply(e.getCode(), map);
	        } catch (AceException | CoseException 
	                | InvalidCipherTextException e) {
	            LOGGER.info("Token invalid: " + e.getMessage());
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	        } catch (Exception e) {
	            LOGGER.severe("Unsupported key wrap algorithm in token: " 
	                    + e.getMessage());
	            return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, null);
            } 
	    } else {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
	        LOGGER.info("Message processing aborted: invalid request");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //2. Check if the token is active, this will only be present if we 
	    // did introspect
	    CBORObject active = claims.get(Constants.ACTIVE);
        if (active != null && active.isFalse()) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
            LOGGER.info("Message processing aborted: Token is not active");
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }

	    //3. Check that the token is not expired (exp)
	    CBORObject exp = claims.get(Constants.EXP);
	    if (exp != null && exp.AsInt64() < this.time.getCurrentTime()) { 
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token is expired");
	        return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }   
      
	    //4. Check if we accept the issuer (iss)
	    CBORObject iss = claims.get(Constants.ISS);
	    if (iss != null) {
	        if (!this.issuers.contains(iss.AsString())) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Token issuer unknown");
	            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	        }
	    }
	    
	    //5. Check if we are the audience (aud)
	    CBORObject aud = claims.get(Constants.AUD);
	    if (aud == null) {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "Token has no audience");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    ArrayList<String> auds = new ArrayList<>();
	    if (aud.getType().equals(CBORType.Array)) {
	        for (int i=0; i<aud.size(); i++) {
	            if (aud.get(i).getType().equals(CBORType.TextString)) {
	                auds.add(aud.get(i).AsString());
	            } //XXX: silently skip aud entries that are not text strings
	        }
	    } else if (aud.getType().equals(CBORType.TextString)) {
	        auds.add(aud.AsString());
	    } else {//Error
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Audience malformed");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "audience malformed");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    boolean audMatch = false;
	    for (String audStr : auds) {
	        if (this.audience.match(audStr)) {
	            audMatch = true;
	        }
	    }
	    if (!audMatch) { 
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience does not apply");
	        return msg.failReply(Message.FAIL_FORBIDDEN, map);
	    }

	    //6. Check if the token has a scope
	    CBORObject scope = claims.get(Constants.SCOPE);
	    if (scope == null) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token has no scope");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //7. Check if any part of the scope is meaningful to us
	    boolean meaningful = false;
	    try {
	    	// M.T. The version of checkScope() with two arguments is invoked
	        meaningful = TokenRepository.getInstance().checkScope(scope, auds);
	    } catch (AceException e) {
	        LOGGER.info("Invalid scope, "
                    + "message processing aborted: " + e.getMessage());
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Scope has invalid format");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	    }
	    if (!meaningful) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Scope does not apply");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token's scope does not apply");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //8. Store the claims of this token
	    CBORObject cti = null;
	    //Check if we have a sid
	    String sid = msg.getSenderId();
	    try {
            cti = TokenRepository.getInstance().addToken(
                    claims, this.ctx, sid);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

	    //9. Create success message
	    //Return the cti or the local identifier assigned to the token
	    CBORObject rep = CBORObject.NewMap();
	    rep.Add(Constants.CTI, cti);
        return msg.successReply(Message.CREATED, rep);
	}
	
	/**
	 * Process a message containing a CWT.
	 * 
	 * Note: The behavior implemented here is the following:
	 * If we have an introspection handler, we try to introspect,
	 * if introspection fails we just return the claims from the CWT,
	 * otherwise we add the claims returned by introspection 
	 * to those of the CWT, possibly overwriting CWT claims with
	 * "fresher" introspection claim having the same id.
	 * 
	 * @param token  the token as CBOR
	 * 
	 * @return  the claims of the CWT
	 * 
	 * @throws AceException 
	 * @throws IntrospectionException 
	 * @throws CoseException
	 * 
	 * @throws Exception  when using a not supported key wrap
	 */
	private Map<Short,CBORObject> processCWT(CBORObject token)
	        throws IntrospectionException, AceException, 
	        CoseException, Exception {
	    CWT cwt = CWT.processCOSE(token.EncodeToBytes(), this.ctx);
	    //Check if we can introspect this token
	    Map<Short, CBORObject> claims = cwt.getClaims();
	   if (this.intro != null) {
	       CBORObject cti = claims.get(Constants.CTI);
	       if (cti != null && cti.getType().equals(CBORType.ByteString)) {
	           Map<Short, CBORObject> introClaims 
	               = this.intro.getParams(cti.GetByteString());
	           if (introClaims != null) {
	               claims.putAll(introClaims);
	           }
	       }
	   }
	   return claims;
    }
    
	/**
	 * Process a message containing a reference token.
	 * 
	 * @param token  the token as CBOR
	 * 
	 * @return  the claims of the reference token
	 * @throws AceException
	 * @throws IntrospectionException 
	 */
    private Map<Short, CBORObject> processRefrenceToken(CBORObject token)
                throws AceException, IntrospectionException {
		// This should be a CBOR String
        if (token.getType() != CBORType.ByteString) {
            throw new AceException("Reference Token processing error");
        }
        
        // Try to introspect the token
        if (this.intro == null) {
            throw new AceException("Introspection handler not found");
        }
        Map<Short, CBORObject> params 
            = this.intro.getParams(token.GetByteString());        
        if (params == null) {
            params = new HashMap<>();
            params.put(Constants.ACTIVE, CBORObject.False);
        }
       
        return params;
	}

    @Override
    public void close() throws AceException {
        if (TokenRepository.getInstance() !=null) {
            TokenRepository.getInstance().close();  
        }
    }	
}