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
package se.sics.ace.as;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * Note: If a client requests a scope that is not supported by (parts) of the 
 * audience this endpoint will just ignore that, assuming that the client will
 * be denied by the PDP anyway. This requires a default deny policy in the PDP.
 * 
 * Note: This endpoint assigns a cti to each issued token based on a counter. 
 * The same value is also used as kid for the proof-of-possession key
 * associated to the token by means of the 'cnf' claim.
 * 
 * Note: This endpoint assumes that the sender Id (the one you get from 
 * Message.getSenderId()) for a secure session created with a raw public key
 * is generated with 
 * org.eclipse.californium.scandium.auth.RawPublicKeyIdentity.getName()
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
     * Boolean for not verify
     */
    private static boolean sign = false;
    
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
     * The client credentials grant type as CBOR-integer
     */
	public static CBORObject clientCredentials 
	    = CBORObject.FromObject(Constants.GT_CLI_CRED);

	/**
	 * The authorizaton_code grant type as CBOR-integer
	 */
	public static CBORObject authzCode 
	    = CBORObject.FromObject(Constants.GT_AUTHZ_CODE);
	
	/**
	 * Converter to create the byte array from the cti number
	 */
	 private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	 
	 /**
	  * The claim types included in tokens generated by this Token instance
	  */
	 private Set<Short> claims;
	 
	 
	 private static Set<Short> defaultClaims = new HashSet<>();
	 
	 static {
	     defaultClaims.add(Constants.CTI);
	     defaultClaims.add(Constants.ISS);
	     defaultClaims.add(Constants.EXI);
	     defaultClaims.add(Constants.AUD);
	     defaultClaims.add(Constants.SCOPE);
	     defaultClaims.add(Constants.CNF);
	 }
	 
	 /**
	  * If true the AUD claim is inserted in the COSE header
      * of a CWT generated by this AS in order to be able to retrieve the right
      * keys when the CWT is presented by the client instead of the RS for 
      * introspection
	  */
	 private boolean setAudHeader = false;
	 
	 /**
	  * Size in bytes of the serverId generated for OSCORE contexts. Default is 1.
	  */
	 private short OS_serverId_size = 1;
	 
	 /*
	  * XXX: Currently OSCORE alg, hkdf, salt and replay window size are fixed to default.
	  * Do we need agility here?
	  */
	 
	/**
	 * Constructor using default set of claims.
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
	    this(asId, pdp, db, time, privateKey, defaultClaims, false, (short)1);
	}
	
	/**   
     * Constructor that allows configuration of the claims included in the token.
     *  
     * @param asId  the identifier of this AS
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param privateKey  the private key of the AS or null if there isn't any
     * @param claims  the claim types to include in tokens issued by this 
     *                Token instance
     * @param setAudInCwtHeader  if true the AUD claim is inserted in the COSE 
     * header of a CWT generated by this AS in order to be able to retrieve the
     * right keys when the CWT is presented by the client instead of the RS for
     * introspection
     * 
     * @throws AceException  if fetching the cti from the database fails
     */
    public Token(String asId, PDP pdp, DBConnector db, 
            TimeProvider time, OneKey privateKey, Set<Short> claims, 
            boolean setAudInCwtHeader) throws AceException {
        this(asId, pdp, db, time, privateKey, claims, setAudInCwtHeader, (short)1);
    }
	
	
	/**   
	 * Constructor that allows configuration of everything.
	 * 
     * @param asId  the identifier of this AS
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param privateKey  the private key of the AS or null if there isn't any
     * @param claims  the claim types to include in tokens issued by this 
     *                Token instance
     * @param setAudInCwtHeader  if true the AUD claim is inserted in the COSE 
     * header of a CWT generated by this AS in order to be able to retrieve the
     * right keys when the CWT is presented by the client instead of the RS for
     * introspection
     * @param oscoreServerIdSize  the size in bytes of the randomly generated OSCORE 
     * server Id for cnf elements.
     * 
     * @throws AceException  if fetching the cti from the database fails
	 */
	public Token(String asId, PDP pdp, DBConnector db, 
            TimeProvider time, OneKey privateKey, Set<Short> claims, 
            boolean setAudInCwtHeader, short oscoreServerIdSize) throws AceException {
		Set<Short> localClaims = claims;
        if(localClaims == null) {
			localClaims = defaultClaims;
		}

	    //Time for checks
        if (asId == null || asId.isEmpty()) {
            LOGGER.severe("Token endpoint's AS identifier was null or empty");
            throw new AceException(
                    "AS identifier must be non-null and non-empty");
        }
        if (pdp == null) {
            LOGGER.severe("Token endpoint's PDP was null");
            throw new AceException(
                    "Token endpoint's PDP must be non-null");
        }
        if (db == null) {
            LOGGER.severe("Token endpoint's DBConnector was null");
            throw new AceException(
                    "Token endpoint's DBConnector must be non-null");
        }
        if (time == null) {
            LOGGER.severe("Token endpoint's TimeProvider was null");
            throw new AceException("Token endpoint's TimeProvider "
                    + "must be non-null");
        }
        //All checks passed
        this.asId = asId;
        this.pdp = pdp;
        this.db = db;
        this.time = time;
        this.privateKey = privateKey;
        this.cti = db.getCtiCounter();
        this.claims = new HashSet<>();
        this.claims.addAll(localClaims);
        this.setAudHeader = setAudInCwtHeader;
        if (oscoreServerIdSize > 0) {
            this.OS_serverId_size = oscoreServerIdSize;
        }
	}

	@Override
	public Message processMessage(Message msg) {
	    if (msg == null) {//This should not happen
	        LOGGER.severe("Token.processMessage() received null message");
	        return null;
	    }
	    LOGGER.log(Level.INFO, "Token received message: " 
	            + msg.getParameters());
	    
	    //1. Check if this client can request tokens
		String id = msg.getSenderId();  
		if (id == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized client: " + id);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
		}
		try {
            if (!this.pdp.canAccessToken(id)) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "unauthorized client: " + id);
            	return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        } catch (AceException e) {
            LOGGER.severe("Database error: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
   
	    //2. Check that this is a supported grant type
	    if (msg.getParameter(Constants.GRANT_TYPE) == null
            //grant type == client credentials implied
	        || msg.getParameter(
	                Constants.GRANT_TYPE).equals(clientCredentials)) {
	        return processCC(msg);
	    } else if (msg.getParameter(Constants.GRANT_TYPE).equals(authzCode)) {
	        return processAC(msg);
	    }
	    CBORObject map = CBORObject.NewMap();
	    map.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);
	    LOGGER.log(Level.INFO, "Message processing aborted: "
	            + "unsupported_grant_type");
	    return msg.failReply(Message.FAIL_BAD_REQUEST, map); 	    
	}
	
	/**
	 * Process a Client Credentials grant.
	 * 
	 * @param msg  the message
	 * @param id  the identifier of the requester
	 * 
	 * @return  the reply
	 */
	private Message processCC(Message msg) {
	    String id = msg.getSenderId();  
		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter(Constants.SCOPE);
		Object scope = null;
		if (cbor == null ) {
			try {
                scope = this.db.getDefaultScope(id);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted (checking scope): "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    if (cbor.getType().equals(CBORType.TextString)) {
		        scope = cbor.AsString();
		    } else if (cbor.getType().equals(CBORType.ByteString)) {
		        scope = cbor.GetByteString();		        
		    } else {
		        CBORObject map = CBORObject.NewMap();
		        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Invalid datatype for scope");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Invalid datatype for scope in message");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		    }
		}
		if (scope == null) {
		    CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No scope found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//4. Check if the request has an audience or if there is a default audience
		cbor = msg.getParameter(Constants.AUDIENCE);
		Set<String> aud = new HashSet<>();
		if (cbor == null) {
		    try {
		        String dAud = this.db.getDefaultAudience(id);
		        if (dAud != null) {
		            aud.add(dAud);
		        }
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted (checking aud): "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    if (cbor.getType().equals(CBORType.Array)) {
		      for (int i=0; i<cbor.size(); i++) {
		          CBORObject audE = cbor.get(i);
		          if (audE.getType().equals(CBORType.TextString)) {
		              aud.add(audE.AsString());
		          } //XXX: Silently skip non-text string audiences
		      }
		    } else if (cbor.getType().equals(CBORType.TextString)) {
		        aud.add(cbor.AsString()); 
		    } else {//error
		        CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Audience malformed");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Audience malformed");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		    }
		}
		if (aud.isEmpty()) {
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		    map.Add(Constants.ERROR_DESCRIPTION, 
		            "No audience found for message");
		    LOGGER.log(Level.INFO, "Message processing aborted: "
		            + "No audience found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

		
		//5. Check if the scope is allowed
		Object allowedScopes = null;
        try {
            allowedScopes = this.pdp.canAccess(msg.getSenderId(), aud, scope);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (checking permissions): "
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
		Short tokenType = null;
        try {
            tokenType = this.db.getSupportedTokenType(aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (creating token): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (tokenType == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Audience incompatible on token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience incompatible on token type");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, 
		           map);
		}
		
		
		byte[] ctiB = buffer.putLong(0, this.cti).array();
        String ctiStr = Base64.getEncoder().encodeToString(ctiB);
        this.cti++;
        

        //Find supported profile

        String profileStr = null;
        try {
            profileStr = this.db.getSupportedProfile(id, aud);
        } catch (AceException e) {
            this.cti--; //roll-back
            LOGGER.severe("Message processing aborted (finding profile): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        if (profileStr == null) {
            this.cti--; //roll-back
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INCOMPATIBLE_PROFILES);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No compatible profile found");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        short profile = Constants.getProfileAbbrev(profileStr);
        
        if (tokenType != AccessTokenFactory.CWT_TYPE 
                && tokenType != AccessTokenFactory.REF_TYPE) {
            this.cti--; //roll-back
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Unsupported token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Unsupported token type");
            return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, map);
        }
       
        String keyType = null; //Save the key type for later
		Map<Short, CBORObject> claims = new HashMap<>();
		
		//ISS SUB AUD EXP NBF IAT CTI SCOPE CNF RS_CNF PROFILE EXI
        for (Short c : this.claims) {
		    switch (c) {
		    case Constants.ISS:
		        claims.put(Constants.ISS, CBORObject.FromObject(this.asId));        
		        break;
            case Constants.SUB:
                claims.put(Constants.SUB, CBORObject.FromObject(id));
                break;
		    case Constants.AUD:
		        //Check if AUDIENCE is a singleton
		        if (aud.size() == 1) {
		            claims.put(Constants.AUD, CBORObject.FromObject(
		                    aud.iterator().next()));
		        } else {
		            claims.put(Constants.AUD, CBORObject.FromObject(aud));
		        }
		        break;
		    case Constants.EXP:
		        long now = this.time.getCurrentTime();
		        long exp = Long.MAX_VALUE;
		        try {
		            exp = this.db.getExpTime(aud);
		        } catch (AceException e) {
		            LOGGER.severe("Message processing aborted (setting exp): "
		                    + e.getMessage());
		            return msg.failReply(
		                    Message.FAIL_INTERNAL_SERVER_ERROR, null);
		        }
		        if (exp == Long.MAX_VALUE) { // == No expiration time found
		            //using default
		            exp = now + expiration;
		        } else {
		            exp = now + exp;
		        }
		        claims.put(Constants.EXP, CBORObject.FromObject(exp));
		        break;
		    case Constants.EXI:
		        long exi = Long.MAX_VALUE;
		        try {
                    exi = this.db.getExpTime(aud);
                } catch (AceException e) {
                    LOGGER.severe("Message processing aborted (setting exp): "
                            + e.getMessage());
                    return msg.failReply(
                            Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
		        if (exi == Long.MAX_VALUE) { // == No expiration time found
		            //using default
		            exi = expiration;
		        }
		        claims.put(Constants.EXI, CBORObject.FromObject(exi)); 
		        break;
		    case Constants.NBF:
		        //XXX: NBF is not configurable in this version
		        now = this.time.getCurrentTime();
		        claims.put(Constants.NBF, CBORObject.FromObject(now));
		        break;
		    case Constants.IAT:
		        now = this.time.getCurrentTime();
		        claims.put(Constants.IAT, CBORObject.FromObject(now));
		        break;
		    case Constants.CTI:
		        claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
		        break;
		    case Constants.SCOPE:
		        claims.put(Constants.SCOPE, 
		                CBORObject.FromObject(allowedScopes));
		        break;
		    case Constants.CNF:
		        CBORObject cnf = msg.getParameter(Constants.CNF);
		        
		        if (cnf == null) { //The client wants to use PSK
		            keyType = "PSK"; //save for later
		            
		            //check if PSK is supported for proof-of-possession
		            try {
		                if (!isSupported(keyType, aud)) {
		                    this.cti--; //roll-back
	                        CBORObject map = CBORObject.NewMap();
	                        map.Add(Constants.ERROR, 
	                                Constants.UNSUPPORTED_POP_KEY);
	                        LOGGER.log(Level.INFO, 
	                                "Message processing aborted: "
	                                + "Unsupported pop key type PSK");
	                        return msg.failReply(
	                                Message.FAIL_BAD_REQUEST, map);
		                }
		            } catch (AceException e) {
                        this.cti--; //roll-back
                        LOGGER.severe("Message processing aborted "
                                + "(finding key type): "
                                + e.getMessage());
                        return msg.failReply(
                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
                    }   
 
		            //Audience supports PSK, make a new PSK
                    try {
                        KeyGenerator kg = KeyGenerator.getInstance("AES");
                        SecretKey key = kg.generateKey();
                        //check if profile == OSCORE
                        if (profile == Constants.COAP_OSCORE) {
                            //Generate OSCORE cnf
                            byte[] keyB = key.getEncoded();
                            CBORObject osc = makeOscoreCnf(keyB, id);
                            claims.put(Constants.CNF, osc);                           
                        } else {//Make a DTLS style psk                         
                            CBORObject keyData = CBORObject.NewMap();
                            keyData.Add(KeyKeys.KeyType.AsCBOR(), 
                                    KeyKeys.KeyType_Octet);
                            keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                                    CBORObject.FromObject(key.getEncoded()));
                            //Note: kid is the same as cti 
                            byte[] kid = ctiB;               
                            keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);

                            OneKey psk = new OneKey(keyData);
                            CBORObject coseKey = CBORObject.NewMap();
                            coseKey.Add(Constants.COSE_KEY, psk.AsCBOR());
                            claims.put(Constants.CNF, coseKey);
                        }
                    } catch (NoSuchAlgorithmException | CoseException e) {
                        this.cti--; //roll-back
                        LOGGER.severe("Message processing aborted "
                                + "(making PSK): " + e.getMessage());
                        return msg.failReply(
                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
                    }
		            
		        } else if (cnf.ContainsKey(Constants.COSE_KID_CBOR)) {
		            //The client requested a specific kid,
	                // assume the client knows what it's doing
	                // i.e. that the RS has that key and can process it
		            
		            //Check that the kid is well-formed
		            CBORObject kidC = cnf.get(Constants.COSE_KID_CBOR);
		            if (!kidC.getType().equals(CBORType.ByteString)) {
		                this.cti--; //roll-back
		                LOGGER.info("Message processing aborted: "
		                        + " Malformed kid in request parameter 'cnf'");
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Malformed kid in 'cnf' parameter");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
		            keyType = "KID";
		            claims.put(Constants.CNF, cnf);
		        } else {//Client has provided a key 
		            //Check what key the client provided
		            OneKey key = null;
		            try {
		                key = getKey(cnf, id);
		            } catch (AceException | CoseException e) {
		                this.cti--; //roll-back
		                LOGGER.severe("Message processing aborted: "
		                        + e.getMessage());
		                if (e.getMessage().startsWith("Malformed")) {
		                    CBORObject map = CBORObject.NewMap();
		                    map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                    map.Add(Constants.ERROR_DESCRIPTION, 
		                            "Malformed 'cnf' parameter in request");
		                    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		                } 
		                return msg.failReply(
		                        Message.FAIL_INTERNAL_SERVER_ERROR, null);
		            }
		            if (key == null) {
		                this.cti--; //roll-back
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Couldn't retrieve RPK");
		                LOGGER.log(Level.INFO, "Message processing aborted: "
		                        + "Couldn't retrieve RPK");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
		            
		            if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_Octet)) {
		                //Client tried to submit a symmetric key => reject
		                this.cti--; //roll-back
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Client tried to provide cnf PSK");
		                LOGGER.log(Level.INFO, "Message processing aborted: "
		                        + "Client tried to provide cnf PSK");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
                    
		            //At this point we assume the client wants to use RPK
		            keyType = "RPK";
		            
		            //Check that the client used this RPK to create this session
		            try {
                        RawPublicKeyIdentity rpkId = new RawPublicKeyIdentity(
                                key.AsPublicKey());
                        if (!rpkId.getName().equals(id)) {
                            this.cti--; //roll-back
                            CBORObject map = CBORObject.NewMap();
                            map.Add(Constants.ERROR, 
                                Constants.UNSUPPORTED_POP_KEY);
                            LOGGER.log(Level.INFO, 
                                    "Message processing aborted: "
                                       + "Client used unauthenticated RPK");
                            return msg.failReply(
                                    Message.FAIL_BAD_REQUEST, map);
                        }
                        
                    } catch (CoseException e) {
                        this.cti--; //roll-back
                        CBORObject map = CBORObject.NewMap();
                        map.Add(Constants.ERROR, 
                            Constants.UNSUPPORTED_POP_KEY);
                        LOGGER.log(Level.INFO, 
                                "Message processing aborted: "
                                        + "Unsupported pop key type RPK");
                        LOGGER.log(Level.FINEST, e.getMessage());
                        return msg.failReply(
                                Message.FAIL_BAD_REQUEST, map);
                    }
                       
		            //Can the audience support this?
		            try {
		                if (!isSupported(keyType, aud)) {
		                    this.cti--; //roll-back
		                    CBORObject map = CBORObject.NewMap();
		                    map.Add(Constants.ERROR, 
                                Constants.UNSUPPORTED_POP_KEY);
		                    LOGGER.log(Level.INFO, 
		                            "Message processing aborted: "
		                                    + "Unsupported pop key type RPK");
		                    return msg.failReply(
		                            Message.FAIL_BAD_REQUEST, map);
		                }
		            } catch (AceException e) {
		                this.cti--; //roll-back
		                LOGGER.severe("Message processing aborted: "
		                        + e.getMessage());
		                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		            }   
                    
		            //Audience support RPK, use provided RPK
		            CBORObject coseKey = CBORObject.NewMap();
		            coseKey.Add(Constants.COSE_KEY, key.AsCBOR());
		            claims.put(Constants.CNF, coseKey);
		        }
		        break;
		    case Constants.PROFILE:
		        claims.put(Constants.PROFILE, CBORObject.FromObject(profile));
		        break;
		    case Constants.RS_CNF:
		        if (keyType != null && keyType.equals("RPK")) {
		           try {
		               Set<CBORObject> rscnfs = makeRsCnf(aud);
		               for (CBORObject rscnf : rscnfs) {
	                       claims.put(Constants.RS_CNF, rscnf);
	                   }
		           } catch (AceException e) {
		               this.cti--; //roll-back
                       LOGGER.severe("Message processing aborted: "
                               + e.getMessage());
                       return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		           }
		        }
		        break;
		    default :
		       LOGGER.severe("Unknown claim type in /token "
		               + "endpoint configuration: " + c);
		       return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);   
		    }
		}

		AccessToken token = null;
		try {
		    token = AccessTokenFactory.generateToken(tokenType, claims);
		} catch (AceException e) {
		    this.cti--; //roll-back
		    LOGGER.severe("Message processing aborted: "
		            + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		
		CBORObject rsInfo = CBORObject.NewMap();
		try {
		    if (!this.db.hasDefaultProfile(id)) {
		        rsInfo.Add(Constants.PROFILE, CBORObject.FromObject(profile));
		    }
		} catch (AceException e) {
		    this.cti--; //roll-back
		    LOGGER.severe("Message processing aborted: "
		            + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		if (keyType != null && keyType.equals("PSK")) {
		    rsInfo.Add(Constants.CNF, claims.get(Constants.CNF));
		}  else if (keyType != null && keyType.equals("RPK")) {
		    Set<CBORObject> rscnfs = new HashSet<>();
            try {
                rscnfs = makeRsCnf(aud);
            } catch (AceException e) {
                this.cti--; //roll-back
                LOGGER.severe("Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		    for (CBORObject rscnf : rscnfs) {
		        rsInfo.Add(Constants.RS_CNF, rscnf);
		    }
		} //Skip cnf if client requested specific KID.

		// M.T.
		// Handle "scope" both as String and as Byte Array
		if (scope instanceof String && !allowedScopes.equals(scope)) {
		    rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}
		if (scope instanceof byte[] && !(Arrays.equals((byte[])allowedScopes, (byte[])scope))) {
		    rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {

		    CwtCryptoCtx ctx = null;
		    try {
		        ctx = EndpointUtils.makeCommonCtx(aud, this.db, 
		                this.privateKey, sign);
		    } catch (AceException | CoseException e) {
		        this.cti--; //roll-back
		        LOGGER.severe("Message processing aborted: "
		                + e.getMessage());
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		    }
		    if (ctx == null) {
		        this.cti--; //roll-back
		        CBORObject map = CBORObject.NewMap();
		        map.Add(Constants.ERROR, 
		                "No common security context found for audience");
		        LOGGER.log(Level.INFO, "Message processing aborted: "
		                + "No common security context found for audience");
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		    }
		    CWT cwt = (CWT)token;
		    Map<HeaderKeys, CBORObject> uHeaders = null;
		    if (this.setAudHeader) {
		        // Add the audience as the KID in the header, so it can be referenced by introspection requests.
		        CBORObject requestedAud = CBORObject.NewArray();
		        for (String a : aud) {
		            requestedAud.Add(a);
		        }
		        uHeaders = new HashMap<>();
		        uHeaders.put(HeaderKeys.KID, requestedAud);
		    }
		    try {
		        rsInfo.Add(Constants.ACCESS_TOKEN, 
		                cwt.encode(ctx, null, uHeaders).EncodeToBytes());
		    } catch (IllegalStateException | InvalidCipherTextException
		            | CoseException | AceException e) {
		        this.cti--; //roll-back
		        LOGGER.severe("Message processing aborted: "
		                + e.getMessage());
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		    }		    
		} else {
		    rsInfo.Add(Constants.ACCESS_TOKEN, token.encode().EncodeToBytes());
		}

		try {
		    this.db.addToken(ctiStr, claims);
		    this.db.addCti2Client(ctiStr, id);
		    this.db.saveCtiCounter(this.cti);
		} catch (AceException e) {
		    this.cti--; //roll-back
		    LOGGER.severe("Message processing aborted: "
		            + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		LOGGER.log(Level.INFO, "Returning token: " + ctiStr);
		LOGGER.log(Level.FINEST, "Claims: " + claims.toString());
		return msg.successReply(Message.CREATED, rsInfo);
	}
	
	/**
	 * Populate RS_CNF
	 * @throws AceException 
	 */
	private Set<CBORObject> makeRsCnf(Set<String> aud) throws AceException {
	    Set<String> rss = new HashSet<>();
	    Set<CBORObject> rscnfs = new HashSet<>();
	    for (String audE : aud) {           
	        rss.addAll(this.db.getRSS(audE));
	    }
	    for (String rs : rss) {
	        OneKey rsKey = this.db.getRsRPK(rs);
	        CBORObject rscnf = CBORObject.NewMap();
	        rscnf.Add(Constants.COSE_KEY_CBOR, rsKey.AsCBOR());
	        rscnfs.add(rscnf);

	    }
	    return rscnfs;
	}
	
	/**
	 * Create an OSCORE_Security_Context CBOR object.
	 * 
	 * @param key  the Master Key
	 * @param clientId  the client identifier
	 * @throws NoSuchAlgorithmException 
	 * @throws AceException 
	 */
	private CBORObject makeOscoreCnf(byte[] key, String clientId) 
	        throws NoSuchAlgorithmException {
	    CBORObject osc = CBORObject.NewMap();
	    CBORObject osccnf = CBORObject.NewMap();
	    osccnf.Add(Constants.OS_MS, key);
	    byte[] serverId = new byte[this.OS_serverId_size];
	    new SecureRandom().nextBytes(serverId);
	 
	    osccnf.Add(Constants.OS_SERVERID, serverId);
	    osccnf.Add(Constants.OS_CLIENTID, clientId.getBytes(
	            Constants.charset));
	    osc.Add(Constants.OSCORE_Security_Context, osccnf);
	    return osc;            
	}
	
	/**
	 * Process an authorization grant message
	 * 
	 * @param msg  the message
	 * 
	 * @return the reply
	 */
	private Message processAC(Message msg) {
	       //3. Check if the request has a grant
        CBORObject cbor = msg.getParameter(Constants.CODE);
        if (cbor == null ) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "No code found for message");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No code found for message");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        if (!cbor.getType().equals(CBORType.TextString)) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid grant format");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Invalid grant format");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        String code = cbor.AsString();
        
	    //4. Check if grant valid and unused
        try {
            if (!this.db.isGrantValid(code)) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_GRANT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "Invalid grant");
                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
            }
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(checking grant): " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
	    //5. Mark grant invalid
        try {
            this.db.useGrant(code);
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(marking grant invalid): " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
	    //6. Return the RS Information
        CBORObject rsInfo = CBORObject.NewMap();
       
        try {
            Map<Short, CBORObject> rsInfoDB = this.db.getRsInfo(code);
            for (Map.Entry<Short, CBORObject> e : rsInfoDB.entrySet()) {
                rsInfo.Add(e.getKey(), e.getValue());
            }
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(collecting RS Info" + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
       
        if (rsInfo == null || !rsInfo.getType().equals(CBORType.Map)) {
            LOGGER.log(Level.SEVERE, "Message processing aborted: "
                    + "no RS information found for grant: " + code);
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_GRANT);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "No token found for grant");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);  
        }
        return msg.successReply(Message.CREATED, rsInfo);
	}

	private boolean isSupported(String keyType, Set<String> aud) 
	        throws AceException {
	    Set<String> keyTypes = this.db.getSupportedPopKeyTypes(aud);
	    return keyTypes.contains(keyType);	    
	}

	/**
	 * Retrieves a key from a cnf structure.
	 * 
	 * @param cnf  the cnf structure
	 * 
	 * @return  the key
	 * 
	 * @throws AceException 
	 * @throws CoseException 
	 */
	private OneKey getKey(CBORObject cnf, String id) 
	        throws AceException, CoseException {
	    CBORObject crpk = null; 
	    if (cnf.ContainsKey(Constants.COSE_KEY_CBOR)) {
	        crpk = cnf.get(Constants.COSE_KEY_CBOR);
	        if (crpk == null) {
	            return null;
	        }
	        return new OneKey(crpk);
	    } else if (cnf.ContainsKey(Constants.COSE_ENCRYPTED_CBOR)) {
	        Encrypt0Message msg = new Encrypt0Message();
            CBORObject encC = cnf.get(Constants.COSE_ENCRYPTED_CBOR);
          try {
              msg.DecodeFromCBORObject(encC);
              OneKey psk = this.db.getCPSK(id);
              if (psk == null) {
                  LOGGER.severe("Couldn't find a key to decrypt cnf parameter");
                  throw new AceException(
                          "No key found to decrypt cnf parameter");
              }
              CBORObject key = psk.get(KeyKeys.Octet_K);
              if (key == null || !key.getType().equals(CBORType.ByteString)) {
                  LOGGER.severe("Corrupt key retrieved from database");
                  throw new AceException("Key error in the database");  
              }
              msg.decrypt(key.GetByteString());
              CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
              return new OneKey(keyData);
          } catch (CoseException e) {
              LOGGER.severe("Error while decrypting a cnf claim: "
                      + e.getMessage());
              throw new AceException("Error while decrypting a cnf parameter");
          }
	    } //Note: We checked the COSE_KID_CBOR case before 
	    throw new AceException("Malformed cnf structure");
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

    @Override
    public void close() throws AceException {
        this.db.saveCtiCounter(this.cti);
        this.db.close();
    }
}
