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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
	 * The filename of the file for storing issued tokens
	 */
	private String tokenfile;
	
	/**
	 * Constructor.
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param registrar  the registrar for registering clients and RSs
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * @param tokenfile  the filename for storing the list of tokens
	 */
	public Token(String asId, PDP pdp, Registrar registrar, 
	        TimeProvider time, CBORObject privateKey, String tokenfile) {
	    this.asId = asId;
	    this.pdp = pdp;
	    this.registrar = registrar;
	    this.tokenfile = tokenfile;
	}
	
	@Override
	public Message processMessage(Message msg) 
	        throws ASException, NoSuchAlgorithmException, 
	        IllegalStateException, InvalidCipherTextException, 
	        CoseException, TokenException, JSONException, IOException {
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
		
		Integer tokenType = this.registrar.getSupportedTokenType(aud);
		if (tokenType == null) {
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, 
		            CBORObject.FromObject("Audience incompatible"));
		}
		
		
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
		String keyType = this.registrar.getPopKeyType(id, aud);
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
		            aud, this.privateKey);
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
		
		saveToken(token, claims);
		
		return msg.successReply(Message.CREATED, rsInfo);
	}
	
	/**
	 * Saves the token in a JSON structure.
	 * [ { "token" : "<raw token data>", "claims" : "<token claims>"}, ...]
	 * 
	 * 
	 * @param token
	 * @param claims
	 * @throws IOException 
	 * @throws JSONException 
	 */
	private void saveToken(AccessToken token, Map<String, CBORObject> claims) 
	        throws JSONException, IOException {
        JSONArray config = new JSONArray();
	    File f = new File(this.tokenfile); 
	    if (f.isFile() && f.canRead()) {
	        FileInputStream fis = new FileInputStream(f);
	        Scanner scanner = new Scanner(fis, "UTF-8" );
	        Scanner s = scanner.useDelimiter("\\A");
	        String configStr = s.hasNext() ? s.next() : "";
	        s.close();
	        scanner.close();
	        fis.close();
	        if (!configStr.isEmpty()) {
	            config = new JSONArray(configStr);   
	        }
	    }
	    JSONObject tokenEntry = new JSONObject();
	    tokenEntry.put("token", token.encode().AsString());
	    tokenEntry.put("claims", claims);
	    config.put(tokenEntry);
	    
        FileOutputStream fos = new FileOutputStream(this.tokenfile, false);
        fos.write(config.toString(4).getBytes());
        fos.close();
	}

	/**
	 * Remove expired tokens from the storage.
	 * 
	 * @throws IOException
	 */
	public void purgeExpiredTokens() throws IOException {
	    JSONArray config = new JSONArray();
        File f = new File(this.tokenfile); 
        if (f.isFile() && f.canRead()) {
            FileInputStream fis = new FileInputStream(f);
            Scanner scanner = new Scanner(fis, "UTF-8" );
            Scanner s = scanner.useDelimiter("\\A");
            String configStr = s.hasNext() ? s.next() : "";
            s.close();
            scanner.close();
            fis.close();
            if (!configStr.isEmpty()) {
                config = new JSONArray(configStr);   
            }
        }
        List<Integer> expired = new LinkedList<>();
        long now = this.time.getCurrentTime();
        for (int i=0; i<config.length(); i++) {
            JSONObject entry = config.getJSONObject(i);
            if (entry.getLong("exp") < now) {
                expired.add(i);
            }
        }
        for (Integer i : expired) {
            config.remove(i);
        }
        FileOutputStream fos = new FileOutputStream(this.tokenfile, false);
        fos.write(config.toString(4).getBytes());
        fos.close();
	}

	/**
	 * Removes a token from the registry
	 * 
	 * @param cti
	 * @throws IOException 
	 */
	public void removeToken(CBORObject cti) throws IOException {
	    JSONArray config = new JSONArray();
        File f = new File(this.tokenfile); 
        if (f.isFile() && f.canRead()) {
            FileInputStream fis = new FileInputStream(f);
            Scanner scanner = new Scanner(fis, "UTF-8" );
            Scanner s = scanner.useDelimiter("\\A");
            String configStr = s.hasNext() ? s.next() : "";
            s.close();
            scanner.close();
            fis.close();
            if (!configStr.isEmpty()) {
                config = new JSONArray(configStr);   
            }
        }
        int remove = -1;
        for (int i=0; i<config.length(); i++) {
            JSONObject entry = config.getJSONObject(i);
            if (entry.getString("cti").equals(cti.AsString())) {
                remove = i;
                break;
            }
        }
        config.remove(remove);
        FileOutputStream fos = new FileOutputStream(this.tokenfile, false);
        fos.write(config.toString(4).getBytes());
        fos.close();
	}
}
