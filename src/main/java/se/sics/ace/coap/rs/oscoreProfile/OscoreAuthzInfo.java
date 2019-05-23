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
package se.sics.ace.coap.rs.oscoreProfile;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;


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
public class OscoreAuthzInfo extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAuthzInfo.class.getName());

	
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
	public OscoreAuthzInfo(TokenRepository tr, List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, CwtCryptoCtx ctx) {
		super(tr, issuers, time, intro, audience, ctx);
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject cbor = null;
        try {
            cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
        } catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        if (!cbor.getType().equals(CBORType.Map)) {
            LOGGER.info("Invalid payload at authz-info: not a cbor map");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        
        CBORObject nonce = cbor.get(Constants.CNONCE);
        //FIXME: store nonce
        
        CBORObject token = cbor.get(Constants.ACCESS_TOKEN);
        return super.processToken(token, msg);
	}


    @Override
    public void close() throws AceException {
       super.close();
        
    }	
}
