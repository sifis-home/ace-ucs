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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

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
import COSE.OneKey;
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
public class Token implements Endpoint, AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(Token.class.getName());

    
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
	 */
	private Long cti = 0L;

	/**
	 * The private key of the AS or null if there isn't any
	 */
	private OneKey privateKey;

    
    /**
     * The client credentials grant type as CBOR-string
     */
	public static CBORObject clientCredentialsStr 
	    = CBORObject.FromObject("client_credentials");

	
	/**
	 * Constructor.
	 * 
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param db  the database connector
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * 
	 * @throws AceException  if fetching the cti from the database fails
	 */
	public Token(String asId, PDP pdp, DBConnector db, 
	        TimeProvider time, OneKey privateKey) throws AceException {
	    this.asId = asId;
	    this.pdp = pdp;
	    this.db = db;
	    this.time = time;
	    this.privateKey = privateKey;
	    this.cti = db.getCtiCounter();
	}
	

	
	@Override
	public Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "Token received message: " 
	            + msg.getParameters());
	    
	    //1. Check that this is a client credentials grant type    
	    if (msg.getParameter("grant_type") == null 
	            || !msg.getParameter("grant_type")
	                .equals(clientCredentialsStr)) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unsupported_grant_type");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	    }
	    	    
		//2. Check if this client can request tokens
		String id = msg.getSenderId();
		if (!this.pdp.canAccessToken(id)) {
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
		    LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized client: " + id);
			return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter("scope");
		String scope = null;
		if (cbor == null ) {
			try {
                scope = this.db.getDefaultScope(id);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    scope = cbor.AsString();
		}
		if (scope == null) {
		    CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No scope found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//4. Check if the request has an audience or if there is a default aud
		cbor = msg.getParameter("aud");
		String aud = null;
		if (cbor == null) {
		    try {
                aud = this.db.getDefaultAudience(id);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    aud = cbor.AsString();
		}
		if (aud == null) {
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		    map.Add(Constants.ERROR_DESCRIPTION, 
		            "No audience found for message");
		    LOGGER.log(Level.INFO, "Message processing aborted: "
		            + "No audience found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		
		//5. Check if the scope is allowed
		String allowedScopes = null;
        try {
            allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (allowedScopes == null) {	
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
		    LOGGER.log(Level.INFO, "Message processing aborted: "
		            + "invalid_scope");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//6. Create token
		//Find supported token type
		Integer tokenType = null;
        try {
            tokenType = this.db.getSupportedTokenType(aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (tokenType == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Audience incompatible on token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience incompatible on token type");
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
		           map);
		}
		
		
		Map<String, CBORObject> claims = new HashMap<>();
		claims.put("iss", CBORObject.FromObject(this.asId));
		claims.put("aud", CBORObject.FromObject(aud));
		claims.put("sub", CBORObject.FromObject(id));
		long now = this.time.getCurrentTime();
		long exp = Long.MAX_VALUE;
        try {
            exp = this.db.getExpTime(aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (exp == Long.MAX_VALUE) {
		    exp = expiration;
		}
		claims.put("exp", CBORObject.FromObject(exp));
		claims.put("iat", CBORObject.FromObject(now));
		String ctiStr = Long.toHexString(this.cti);
		this.cti++;
		claims.put("cti", CBORObject.FromObject(ctiStr.getBytes()));
		claims.put("scope", CBORObject.FromObject(allowedScopes));

		//Find supported profile
		String profile = null;
        try {
            profile = this.db.getSupportedProfile(id, aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (profile == null) {
		    CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "No compatible profile found");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No compatible profile found");
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		}
		
		if (tokenType != AccessTokenFactory.CWT_TYPE 
		        && tokenType != AccessTokenFactory.REF_TYPE) {
		    CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Unsupported token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Unsupported token type");
		    return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, map);
		}
		
		//Find supported key type for proof-of-possession
		String keyType = "";
        try {
            keyType = this.db.getSupportedPopKeyType(id, aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		switch (keyType) {
		case "PSK":
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                SecretKey key = kg.generateKey();
                CBORObject psk = CBORObject.FromObject(key.getEncoded());
                claims.put("cnf", psk);
            } catch (NoSuchAlgorithmException e) {
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }	    
		    break;
		case "RPK":
		    CBORObject crpk = msg.getParameter("cnf");
		    OneKey rpk = null;
		    if (crpk == null) {
		        //Try to get the RPK from the DB
		        try {
                    rpk = this.db.getCRPK(id);
                } catch (AceException e) {
                    LOGGER.severe("Message processing aborted: "
                            + e.getMessage());
                    return msg.failReply(
                            Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
		    } else {
		        try {
                    rpk = new OneKey(crpk);
                } catch (CoseException e) {
                    LOGGER.severe("Message processing aborted: "
                            + e.getMessage());
                    return msg.failReply(
                            Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
		    }
		    if (rpk == null) {
		        CBORObject map = CBORObject.NewMap();
		        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		        map.Add(Constants.ERROR_DESCRIPTION, 
		                "Client failed to provide RPK");
		        LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Client failed to provide RPK");
		        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		    }
		    claims.put("cnf", crpk);
		    break;
		default :
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Unsupported key type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Unsupported key type");
		    return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, map);
		}
		
		AccessToken token = null;
        try {
            token = AccessTokenFactory.generateToken(tokenType, claims);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		CBORObject rsInfo = CBORObject.NewMap();
		rsInfo.Add(Constants.PROFILE, CBORObject.FromObject(profile));
		rsInfo.Add(Constants.CNF, claims.get("cnf"));
		if (!allowedScopes.equals(scope)) {
		    rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {
		    		    
		    CwtCryptoCtx ctx = null;
            try {
                ctx = makeCommonCtx(aud);
            } catch (AceException | CoseException e) {
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		    if (ctx == null) {
		        CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, 
	                    "No common security context found for audience");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "No common security context found for audience");
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		    }
		    CWT cwt = (CWT)token;
		    try {
                rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx));
            } catch (IllegalStateException | InvalidCipherTextException
                    | CoseException | AceException e) {
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    rsInfo.Add(Constants.ACCESS_TOKEN, token.encode());
		}
		
		try {
            this.db.addToken(ctiStr, claims);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		 LOGGER.log(Level.INFO, "Returning token: " + ctiStr);
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
	 * @param aud  the audience

	 * @return  a common crypto context or null if there isn't any
	 * 
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
	 * @throws CoseException 
	 */
	private List<Recipient> makeRecipients(String aud, COSEparams cose)
	        throws AceException, CoseException {
	    List<Recipient> rl = new ArrayList<>();
	    for (String rs : this.db.getRSS(aud)) {
	        Recipient r = new Recipient();
	        r.addAttribute(HeaderKeys.Algorithm, 
	                cose.getKeyWrap().AsCBOR(), 
	                Attribute.UNPROTECTED);
	        CBORObject key = CBORObject.NewMap();
	        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
	        key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
	                this.db.getRsPSK(rs)));
	        OneKey coseKey = new OneKey(key);
	        r.SetKey(coseKey); 
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

    @Override
    public void close() throws AceException {
        this.db.saveCtiCounter(this.cti);
        //this.db.close();
    }
}
