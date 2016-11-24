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
package se.sics.ace.as;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.Recipient;

import se.sics.ace.AccessToken;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.AceException;
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
	 * The database connector for storing and retrieving stuff.
	 */
	private DBConnector db;
	
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
	 * FIXME: need to save this to avoid resetting each time this is restarted
	 */
	private Long cti = 0L;

	/**
	 * The private key of the AS or null if there isn't any
	 */
	private CBORObject privateKey;
	
	
	/**
	 * Constructor.
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param db  the database connector
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * @param tokenfile  the filename for storing the list of tokens
	 */
	public Token(String asId, PDP pdp, DBConnector db, 
	        TimeProvider time, CBORObject privateKey) {
	    this.asId = asId;
	    this.pdp = pdp;
	    this.db = db;
	    this.time = time;
	    this.privateKey = privateKey;
	}
	
	@Override
	public Message processMessage(Message msg) 
	        throws AceException, NoSuchAlgorithmException, 
	        IllegalStateException, InvalidCipherTextException, 
	        CoseException, AceException {
		//1. Check if this client can request tokens
		String id = msg.getSenderId();
		if (!this.pdp.canAccessToken(id)) {
			return msg.failReply(Message.FAIL_UNAUTHORIZED, null);
		}
		
		//2. Check if this client can request this type of token
		CBORObject cbor = msg.getParameter("scope");
		String scope = null;
		if (cbor == null ) {
			scope = this.db.getDefaultScope(id);
		} else {
		    scope = cbor.AsString();
		}
		if (scope == null) {
		    return msg.failReply(Message.FAIL_BAD_REQUEST, 
		            CBORObject.FromObject("request lacks scope"));
		}
		cbor = msg.getParameter("aud");
		String aud = null;
		if (cbor == null) {
		    aud = this.db.getDefaultAudience(id);
		} else {
		    aud = cbor.AsString();
		}
		if (aud == null) {
		    return msg.failReply(Message.FAIL_BAD_REQUEST,
		            CBORObject.FromObject("request lacks audience"));
		}
		String allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
		
		if (allowedScopes == null) {		
			return msg.failReply(Message.FAIL_FORBIDDEN, null);
		}
		
		//4. Create token
		//Find supported token type
		
		Integer tokenType = this.db.getSupportedTokenType(aud);
		if (tokenType == null) {
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
		            CBORObject.FromObject(
		                    "Audience incompatible on token type"));
		}
		
		
		Map<String, CBORObject> claims = new HashMap<>();
		claims.put("iss", CBORObject.FromObject(this.asId));
		claims.put("aud", CBORObject.FromObject(aud));
		claims.put("sub", CBORObject.FromObject(id));
		long now = this.time.getCurrentTime();
		long exp = this.db.getExpTime(aud);
		if (exp == Long.MAX_VALUE) {
		    exp = expiration;
		}
		claims.put("exp", CBORObject.FromObject(exp));
		claims.put("iat", CBORObject.FromObject(now));
		byte[] cti = Long.toHexString(this.cti).getBytes();
		this.cti++;
		claims.put("cti", CBORObject.FromObject(cti));
		String ctiStr = Base64.getEncoder().encodeToString(cti);
		claims.put("scope", CBORObject.FromObject(scope));

		//Find supported profile
		String profile = this.db.getSupportedProfile(id, aud);
		if (profile == null) {
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
                    CBORObject.FromObject(
                            "No compatible profile found"));
		}
		
		if (tokenType != AccessTokenFactory.CWT_TYPE 
		        && tokenType != AccessTokenFactory.REF_TYPE) {
		    return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, 
		            CBORObject.FromObject("Unsupported token type"));
		}
		
		//Find supported key type for proof-of-possession
		String keyType = this.db.getSupportedPopKeyType(id, aud);
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
		    		    
		    CwtCryptoCtx ctx = makeCommonCtx(aud);
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
		
		this.db.addToken(ctiStr, claims);
		
		return msg.successReply(Message.CREATED, rsInfo);
	}
	
	/**
	 * Remove expired tokens from the storage.
	 * 
	 * @throws AceException 
	 */
	public void purgeExpiredTokens() throws AceException {
	    this.db.purgeExpiredTokens(this.time.getCurrentTime());
	}

	/**
	 * Removes a token from the registry
	 * 
	 * @param cti  the token identifier Base64 encoded
	 * @throws AceException 
	 */
	public void removeToken(String cti) throws AceException {
	    this.db.deleteToken(cti);
	}
	
	/**
	 * Create a common CWT crypto context for the given audience.
	 * 
	 * @param aud
	 * @param cose
	 * @return
	 * @throws CoseException 
	 * @throws AceException 
	 */
	private CwtCryptoCtx makeCommonCtx(String aud) 
	        throws AceException, CoseException {
	    COSEparams cose = this.db.getSupportedCoseParams(aud);
	    if (cose == null) {
	        return null;
	    }
	    MessageTag tag = cose.getTag();
	    switch (tag) {
	    case Encrypt:
	        AlgorithmID ealg = cose.getAlg();
	        return CwtCryptoCtx.encrypt(makeRecipients(aud, cose), 
	                ealg.AsCBOR());
	    case Encrypt0:
	        byte[] ekey = getCommonSecretKey(aud);
	        if (ekey == null) {
	            return null;
	        }
	        return CwtCryptoCtx.encrypt0(ekey, cose.getAlg().AsCBOR());
	    case MAC:

	        return CwtCryptoCtx.mac(makeRecipients(aud, cose), 
	                cose.getAlg().AsCBOR());
	    case MAC0:
	        byte[] mkey = getCommonSecretKey(aud);
	        if (mkey == null) {
	            return null;
	        }
	        return CwtCryptoCtx.mac0(mkey, cose.getAlg().AsCBOR());
	    case Sign:
	        // Access tokens with multiple signers not supported
	        return null;
	    case Sign1:

	        return CwtCryptoCtx.sign1Create(
	                this.privateKey, cose.getAlg().AsCBOR());
	    default:
	        throw new IllegalArgumentException("Unknown COSE message type");
	    }
	}

	/**
	 * Create a recipient list for an audience.
	 * 
	 * @param aud  the audience
	 * @return  the recipient list
	 * @throws AceException 
	 */
	private List<Recipient> makeRecipients(String aud, COSEparams cose)
	        throws AceException {
	    List<Recipient> rl = new ArrayList<>();
	    for (String rs : this.db.getRSS(aud)) {
	        Recipient r = new Recipient();
	        r.addAttribute(HeaderKeys.Algorithm, 
	                cose.getKeyWrap().AsCBOR(), 
	                Attribute.UnprotectedAttributes);
	        CBORObject key = CBORObject.NewMap();
	        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
	        key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
	                this.db.getRsPSK(rs)));
	        r.SetKey(key); 
	        rl.add(r);
	    }
	    return rl;
	}

	/**
	 * Tries to find a common PSK for the given audience.
	 * 
	 * @param aud  the audience
	 * @return  a common PSK or null if there isn't any
	 * @throws AceException 
	 */
	private byte[] getCommonSecretKey(String aud) throws AceException {
	    Set<String> rss = this.db.getRSS(aud);
	    byte[] key = null;
	    for (String rs : rss) {
	        byte[] secKey = this.db.getRsPSK(rs);
	        if (secKey == null) {
	            return null;
	        }
	        if (key == null) {
	            key = Arrays.copyOf(secKey, secKey.length);
	        } else {
	            if (!Arrays.equals(key, secKey)) {
	                return null;
	            }
	        }
	    }
	    return key;
	}
}
