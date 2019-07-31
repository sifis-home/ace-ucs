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
import org.junit.Assert;

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
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;
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
public class AuthzInfoGroupOSCORE extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(AuthzInfo.class.getName());
	
    /**
     * Temporary storage for the CNF claim
     */
    private CBORObject cnf;
    
    /**
     * OSCORE groups active under the Group Manager
     */
	// TODO: When included in the referenced Californium, use californium.elements.util.Bytes rather than Integers as map keys 
	private Map<Integer, GroupInfo> activeGroups;
	
	/**
	 * Constructor.
	 * 
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 * @param tokenFile  the file where to save tokens when persisting
	 * @param scopeValidator  the application specific scope validator 
	 * @param checkCnonce  true if this RS uses cnonces for freshness validation
	 * @param activeGroups   OSCORE groups active under the Group Manager
	 * @throws AceException  if the token repository is not initialized
	 * @throws IOException 
	 */
	public AuthzInfoGroupOSCORE(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, CwtCryptoCtx ctx, String tokenFile, 
			ScopeValidator scopeValidator, boolean checkCnonce) 
			        throws AceException, IOException {
		
		super(issuers, time, intro, audience, ctx, tokenFile, 
		        scopeValidator, checkCnonce);
		
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject token = null;
	    CBORObject cbor = null;
	    boolean provideSignInfo = false;
	    boolean providePubKeyEnc = false;
	    boolean invalid = false;
	    
	    try {
	    	cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    }
	    catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid payload");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
	    	
	    // The payload of the Token POST message is a map. Retrieve the Token from it.
	    // This is a possible case when the joining node asks the Group Manager for
	    // information on the signature algorithm and parameters used in the OSCORE group.
	    if (cbor.getType().equals(CBORType.Map)) {
	    		
	    	token = cbor.get(CBORObject.FromObject(Constants.ACCESS_TOKEN));
	    		
	    	if (cbor.ContainsKey("sign_info")) {
	    		if (cbor.get("sign_info").equals(CBORObject.Null)) {
	    			provideSignInfo = true;
	    		}
	    		else invalid = true;
	    	}
	    	
	    	if (cbor.ContainsKey("pub_key_enc")) {
	    		if (cbor.get("pub_key_enc").equals(CBORObject.Null)) {
	    			providePubKeyEnc = true;
	    		}
	    		else invalid = true;
	    	}
	    	
	    }
	    // The payload of the Token POST message consists of the Access Token only.
	    // This is the expected usual case, when the client does not include additional parameters.
	    else {
	    		
	    	token = cbor;
	    		
	    }
	    
        if (token == null) {
            LOGGER.info("Missing manadory parameter 'access_token'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Missing mandatory parameter 'access_token'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        if (invalid) {
            LOGGER.info("Invalid format for 'sign_info' and 'pub_key_enc'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Invalid format for 'sign_info' and 'pub_key_enc'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
	    
	    Message reply = super.processToken(token, msg);
        if (reply.getMessageCode() != Message.CREATED) {
            return reply;
        }
        
        if (this.cnf == null) {//Should never happen, caught in TokenRepository.
            LOGGER.info("Missing required parameter 'cnf'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
	    
	    //Return the cti or the local identifier assigned to the token
	    CBORObject rep = CBORObject.NewMap();
	    CBORObject responseMap = CBORObject.DecodeFromBytes(reply.getRawPayload());
	    CBORObject cti = responseMap.get(CBORObject.FromObject(Constants.CTI));
	    rep.Add(Constants.CTI, cti);
        
	    if (provideSignInfo) {
	    	
	    }
	    
	    if (providePubKeyEnc) {
	    	/*
	    	String scopeStr;
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	scopeStr = scopeElement.AsString();
	    	
	    	// The first 'groupIdPrefixSize' pairs of characters are the Group ID Prefix.
        	// This string is surely hexadecimal, since it passed the early check against the URI path to the join resource.
        	String prefixStr = scopeStr.substring(0, 2 * groupIdPrefixSize);
        	byte[] prefixByteStr = hexStringToByteArray(prefixStr);
        	
        	// Retrieve the entry for the target group, using the Group ID Prefix
        	GroupInfo myGroup = activeGroups.get(Integer.valueOf(GroupInfo.bytesToInt(prefixByteStr)));
	    	rep.Add("pub_key_enc", myGroup.getCsKeyEnc());
	    	*/
	    }
	    
	    LOGGER.info("Successfully processed DTLS token");
        return msg.successReply(reply.getMessageCode(), rep);
	}
    
	public synchronized void setActiveGroups(Map<Integer, GroupInfo> activeGroups) {
		this.activeGroups = activeGroups;
	}
	
	@Override
	protected synchronized void processOther(Map<Short, CBORObject> claims) {
	    this.cnf = claims.get(Constants.CNF);
	}
	
    @Override
    public void close() throws AceException {
       super.close();
        
    }
}