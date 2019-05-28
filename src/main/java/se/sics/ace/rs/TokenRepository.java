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
package se.sics.ace.rs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * This class is used to store valid access tokens and 
 * provides methods to check them against an incoming request.  It is the 
 * responsibility of the request handler to call this class. 
 * 
 * Note that this class assumes that every token has a 'scope',
 * 'aud', and 'cnf'.  Tokens
 * that don't have these will lead to request failure.
 * 
 * If the token has no cti, this class will use the hashCode() of the claims
 * Map to generate a local cti.
 * 
 * This class is implemented as a singleton to ensure that all users see
 * the same repository (and yes I know that parameterized singletons are bad 
 * style, go ahead and suggest a better solution).
 *  
 * @author Ludwig Seitz
 *
 */
public class TokenRepository implements AutoCloseable {
	
    /**
     * Return codes of the canAccess() method
     */
    public static final int OK = 1;
    
    /**
     * Return codes of the canAccess() method. 4.01 Unauthorized
     */
    public static final int UNAUTHZ = 0;
    
    /**
     * Return codes of the canAccess() method. 4.03 Forbidden
     */ 
    public static final int FORBID = -1;
    
    /**
     * Return codes of the canAccess() method. 4.05 Method Not Allowed
     */
    public static final int METHODNA = -2;

    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(TokenRepository.class.getName());
     
    /**
     * Is this closed?
     */
    private boolean closed = true;
    
	/**
	 * Maps the base64 encoded cti to the claims of the corresponding token
	 */
	private Map<String, Map<Short, CBORObject>> cti2claims;
	
	
	/**
	 * Map key identifiers collected from the access tokens to keys
	 */
	protected Map<String, OneKey> kid2key;
	
	/**
	 * Map the base64 encoded cti of a token to the corresponding pop-key kid
	 */
	protected Map<String, String>cti2kid;
	
	
	/**
	 * Map a subject identity to the kid they use
	 */
	private Map<String, String>sid2kid;
	
	/**
	 * The scope validator
	 */
	private ScopeValidator scopeValidator;
	
	/**
     * The filename + path for the JSON file in which the tokens are stored
     */
    private String tokenFile;

    /**
	 * The counter used to generate the cnonces.
	 * -1 means we don't use cnonces.
	 */
	private Integer cnonceCounter = -1;
	
	/**
	 * The last seen nonce
	 */
	private int cnonceSeen;
	
	/**
     * The size of the replay window
     */
    private int cnonceWindowSize;

	/**
	 * Cnonce replay window, 
	 */
	private int cnonceWindow;
	
	/**
	 * Cnonce HMAC key (32 bytes)
	 */
	private byte[] cnonceKey;
	
	/**
	 * The time provider providing local time for this RS
	 */
	private TimeProvider time;
	
	/**
	 * The singleton instance
	 */
	private static TokenRepository singleton = null;
	
	
	/**
	 * The singleton getter
	 * @return  the singleton repository
	 * @throws AceException  if the repository is not initialized
	 */
	public static TokenRepository getInstance() throws AceException {
	    if (singleton == null) {
	        throw new AceException("Token repository not created");
	    }
	    return singleton;
	}
	
	/**
	 * Creates the one and only instance of the token repo and loads the 
	 * existing tokens from a JSON file is there is one.
     * 
     * The JSON file stores the tokens as a JSON array of JSON maps,
     * where each map represents the claims of a token, String mapped to
     * the Base64 encoded byte representation of the CBORObject.
     * 
     * @param scopeValidator  the application specific scope validator
     * @param tokenFile  the file storing the existing tokens, if the file
     *     does not exist it is created
     * @param ctx  the crypto context for reading encrypted tokens
	 * 
	 * @param scopeValidator  the validator for scopes
	 * @param tokenFile  the file where to save tokens
	 * @param ctx  the crypto context
	 * @param time  the time provider for this RS
	 * @param useCnonces  true if this RS is to use client-nonces for access 
	 *     token freshness verification
	 * @param cnonceReplayWindowSize  the cnonce replay window size (or null to
	 *     use the default)
	 * @throws AceException
	 * @throws IOException
	 */
	public static void create(ScopeValidator scopeValidator, 
            String tokenFile, CwtCryptoCtx ctx, TimeProvider time, 
            boolean useCnonces, Integer cnonceReplayWindowSize)
                    throws AceException, IOException {
	    if (singleton != null) {
	        throw new AceException("Token repository already exists");
	    }
	    singleton = new TokenRepository(scopeValidator, tokenFile, ctx, 
	            time, useCnonces, cnonceReplayWindowSize);
	}
	
	/**
	 * Creates a new token repository and loads the existing tokens
	 * from a JSON file is there is one.
	 * 
	 * The JSON file stores the tokens as a JSON array of JSON maps,
	 * where each map represents the claims of a token, String mapped to
	 * the Base64 encoded byte representation of the CBORObject.
	 * 
	 * @param scopeValidator  the application specific scope validator
	 * @param tokenFile  the file storing the existing tokens, if the file
	 *     does not exist it is created
	 * @param ctx  the crypto context for reading encrypted tokens
	 * @param useCnonces  true if this RS is to use client-nonces for access 
     *     token freshness verification
	 * @param cnonceReplayWindowSize  the cnonce replay window size (or null to
     *     use the default)
	 * @throws IOException 
	 * @throws AceException 
	 */
	protected TokenRepository(ScopeValidator scopeValidator, 
	        String tokenFile, CwtCryptoCtx ctx, TimeProvider time,
	        boolean useCnonces, Integer cnonceWindowSize) 
			        throws IOException, AceException {
	    this.closed = false;
	    this.cti2claims = new HashMap<>();
	    this.kid2key = new HashMap<>();
	    this.cti2kid = new HashMap<>();
	    this.sid2kid = new HashMap<>();
	    this.scopeValidator = scopeValidator;
	    this.time = time;
	    if (useCnonces) {
	        this.cnonceCounter = 1;
	        this.cnonceSeen = 0;
	        this.cnonceKey = new byte[32];
	        SecureRandom sr = new SecureRandom();
	        sr.nextBytes(this.cnonceKey);  
	        this.cnonceWindow = 0;
	        if (cnonceWindowSize == null) {
	            //Use default
	            this.cnonceWindowSize = 30;
	        } else if (this.cnonceWindowSize > 32) {
	            throw new IllegalArgumentException(
	                    "cnonceWindow size must be between 0 and 32");
	        } else {
	            this.cnonceWindowSize = cnonceWindowSize;
	        }
	    }
	    if (tokenFile == null) {
	        throw new IllegalArgumentException("Must provide a token file path");
	    }
	    this.tokenFile = tokenFile;
	    File f = new File(this.tokenFile);
	    if (!f.exists()) {
	        return; //File will be created if tokens are added
	    }
	    FileInputStream fis = new FileInputStream(f);
        Scanner scanner = new Scanner(fis, "UTF-8");
        Scanner s = scanner.useDelimiter("\\A");
        String configStr = s.hasNext() ? s.next() : "";
        s.close();
        scanner.close();
        fis.close();
        JSONArray config = null;
        if (!configStr.isEmpty()) {
            config = new JSONArray(configStr);
            Iterator<Object> iter = config.iterator();
            while (iter.hasNext()) {
                Object foo = iter.next();
                if (!(foo instanceof JSONObject)) {
                    throw new AceException("Token file is malformed");
                }
                JSONObject token =  (JSONObject)foo;
                Iterator<String> iterToken = token.keys();
                Map<Short, CBORObject> params = new HashMap<>();
                while (iterToken.hasNext()) {
                    String key = iterToken.next();  
                    params.put(Short.parseShort(key), 
                            CBORObject.DecodeFromBytes(
                                    Base64.getDecoder().decode(
                                            token.getString((key)))));
                }
                this.addToken(params, ctx, null);
            }
        }
	}

	/**
	 * Add a new Access Token to the repo.  Note that this method DOES NOT 
	 * check the validity of the token.
	 * 
	 * @param claims  the claims of the token
	 * @param ctx  the crypto context of this RS  
	 * @param sid  the subject identity of the user of this token, or null
	 *     if not needed
	 *     
	 * @return  the cti or the local id given to this token
	 * 
	 * @throws AceException 
	 */
	public synchronized CBORObject addToken(Map<Short, CBORObject> claims, 
	        CwtCryptoCtx ctx, String sid) throws AceException {
	    
	    //Check for cnonce
	    checkNonce(claims);
	    
		CBORObject so = claims.get(Constants.SCOPE);
		if (so == null) {
			throw new AceException("Token has no scope");
		}

		CBORObject cticb = claims.get(Constants.CTI);
		String cti = null;
		if (cticb == null) {
		    cticb = CBORObject.FromObject(
		            buffer.putInt(0, claims.hashCode()).array());
			cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
			claims.put(Constants.CTI, cticb);
		} else if (!cticb.getType().equals(CBORType.ByteString)) {
		    LOGGER.info("Token's cti in not a ByteString");
            throw new AceException("Cti has invalid format");
        } else {		
		    cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
		}
		
		//Check for duplicate cti
		if (this.cti2claims.containsKey(cti)) {
		    throw new AceException("Duplicate cti");
		}

		//Store the pop-key
		CBORObject cnf = claims.get(Constants.CNF);
        if (cnf == null) {
            LOGGER.severe("Token has not cnf");
            throw new AceException("Token has no cnf");
        }
        if (!cnf.getType().equals(CBORType.Map)) {
            LOGGER.severe("Malformed cnf in token");
            throw new AceException("cnf claim malformed in token");
        }
        
        if (cnf.getKeys().contains(Constants.COSE_KEY_CBOR)) {
            CBORObject ckey = cnf.get(Constants.COSE_KEY_CBOR);
            try {
              OneKey key = new OneKey(ckey);
              processKey(key, sid, cti);
            } catch (CoseException e) {
                LOGGER.severe("Error while parsing cnf element: " 
                        + e.getMessage());
                throw new AceException("Invalid cnf element: " 
                        + e.getMessage());
            } 
        } else if (cnf.getKeys().contains(Constants.COSE_ENCRYPTED_CBOR)) {
            Encrypt0Message msg = new Encrypt0Message();
            CBORObject encC = cnf.get(Constants.COSE_ENCRYPTED_CBOR);
          try {
              msg.DecodeFromCBORObject(encC);
              msg.decrypt(ctx.getKey());
              CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
              OneKey key = new OneKey(keyData);
              processKey(key, sid, cti);
          } catch (CoseException e) {
              LOGGER.severe("Error while decrypting a cnf claim: "
                      + e.getMessage());
              throw new AceException("Error while decrypting a cnf claim");
          }
        } else if (cnf.getKeys().contains(Constants.COSE_KID_CBOR)) {
            String kid = null;
            CBORObject kidC = cnf.get(Constants.COSE_KID_CBOR);
            if (kidC.getType().equals(CBORType.ByteString)) {
                kid = new String(
                        kidC.GetByteString(), Constants.charset);
            } else {
                LOGGER.severe("kid is not a byte string");
                throw new AceException("cnf contains invalid kid");
            }
            if (!this.kid2key.containsKey(kid)) {
                LOGGER.info("Token refers to unknown kid");
                throw new AceException("Token refers to unknown kid");
            }
            //Store the association between token and known key
            this.cti2kid.put(cti, kid);  
            // ... and between subject id and key if sid was given
            if (sid != null) {
                this.sid2kid.put(sid, kid);
            }
        } else {
            LOGGER.severe("Malformed cnf claim in token");
            throw new AceException("Malformed cnf claim in token");
        }
        
        //Now store the claims. Need deep copy here
        Map<Short, CBORObject> foo = new HashMap<>();
        foo.putAll(claims);
        this.cti2claims.put(cti, foo);
        
        persist();
        
        return cticb;
	}
	
	/**
	 * Implements the nonce checking
	 * @throws AceException 
	 */
	private void checkNonce(Map<Short, CBORObject> claims) throws AceException {
	    if (this.cnonceCounter == -1) {//Means we are not using the client nonces
	        return;
	    }
	    CBORObject cnonce = claims.get(Constants.CNONCE);
	    if (cnonce == null) {
	        LOGGER.info("Expected a cnonce but found none");
	        throw new AceException("cnonce expected but not found");
	    }

	    if (!cnonce.getType().equals(CBORType.ByteString)) {
	        throw new AceException("Invalid cnonce type");
	    }
	    byte[] cnonceB = cnonce.GetByteString();
	    if (cnonceB.length != 4+32) {//4 byte for the int counter, 16 bytes HMAC
	        throw new AceException("Invalid cnonce length");
	    }
	    byte[] mac = new byte[32];
	    byte[] counter = new byte[4];
	    mac = Arrays.copyOfRange(cnonceB, 0, 32);
	    counter = Arrays.copyOfRange(cnonceB, 32, 36);
	    byte[] macExpected;
	    //Verify MAC
	    try {
	        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");

	        SecretKeySpec secret_key = new SecretKeySpec(
	                this.cnonceKey, "HmacSHA256");
	        sha256_HMAC.init(secret_key);

	        macExpected = sha256_HMAC.doFinal(counter);
	    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
	        LOGGER.severe("Error while verifying cnonce: " + e.getMessage());
	        throw new AceException("Nonce verification failed");
	    }

	    if (!Arrays.equals(mac, macExpected)) {
	        throw new AceException("cnonce invalid");
	    }

	    //Check if nonce is in the replay window
	    ByteBuffer b = ByteBuffer.wrap(counter);
	    int counterI = b.getInt();
	    checkIncomingCounter(counterI);
	}

	/**
	 * Check an incoming cnonce counter
	 * @param counter
	 * @throws AceException
	 */
	private synchronized void checkIncomingCounter(int counter) throws AceException {
	    if (counter > this.cnonceSeen) {
	        // Update the replay window
	        int shift = counter - this.cnonceSeen;
	        this.cnonceWindow = this.cnonceWindow << shift;
	        this.cnonceSeen = counter;
	    } else if (counter == this.cnonceSeen) {
	        throw new AceException("cnonce replayed");
	    } else { // counter < this.cnonceSeen
	        if (counter + this.cnonceWindowSize < this.cnonceSeen) {
	            LOGGER.severe("cnonce too old");
	            throw new AceException("cnonce expired");
	        }
	        // seq+replay_window_size > recipient_seq
	        int shift = this.cnonceSeen - counter;
	        int pattern = 1 << shift;
	        int verifier = this.cnonceWindow & pattern;
	        verifier = verifier >> shift;
	        if (verifier == 1) {
	            throw new AceException("cnonce replayed");
	        }
	        this.cnonceWindow = this.cnonceWindow | pattern;
	    }
	}


    /**
	 * Add the mappings for the cnf-key.
	 * 
	 * @param key  the key
	 * @param sid  the subject identifier
	 * @param cti  the token's identifier
	 * 
	 * @throws AceException
	 * @throws CoseException
	 */
	private void processKey(OneKey key, String sid, String cti) 
	        throws AceException, CoseException {
	    
	    String kid = null;
	    if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_Octet)) {
	        CBORObject kidC = key.get(KeyKeys.KeyId);

	        if (kidC == null) {
	            LOGGER.severe("kid not found in COSE_Key");
	            throw new AceException("COSE_Key is missing kid");
	        } else if (kidC.getType().equals(CBORType.ByteString)) {
	            kid = new String(kidC.GetByteString(), Constants.charset);
	        } else {
	            LOGGER.severe("kid is not a byte string");
	            throw new AceException("COSE_Key contains invalid kid");
	        }
	    } else {//Key type is EC2
	        RawPublicKeyIdentity rpk =
	                new RawPublicKeyIdentity(key.AsPublicKey());
	        kid = rpk.getName();
	    }
        this.cti2kid.put(cti, kid);
        this.kid2key.put(kid, key);
        if (sid != null) {
            this.sid2kid.put(sid, kid);
        } else if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2)) {
            //Scandium needs a special mapping for raw public keys
            RawPublicKeyIdentity rpk 
                = new RawPublicKeyIdentity(key.AsPublicKey());
            this.sid2kid.put(rpk.getName(), kid);
        } else { //Take the kid as sid
            this.sid2kid.put(kid, kid);
        }        
    }

    /**
	 * Remove an existing token from the repository.
	 * 
	 * @param cti  the cti of the token to be removed Base64 encoded.
	 * @throws AceException 
	 */
	public synchronized void removeToken(String cti) throws AceException {
	    if (cti == null) {
            throw new AceException("Cti is null");
        } 
	    
        //Remove the claims
        this.cti2claims.remove(cti);
 
		//Remove the mapping to the pop key
		this.cti2kid.remove(cti);
		
		//Remove unused keys
		Set<String> remove = new HashSet<>();
		for (String kid : this.kid2key.keySet()) {
		    if (!this.cti2kid.containsValue(kid)) {
		        remove.add(kid);
		    }
		}
		for (String kid : remove) {
		    this.kid2key.remove(kid);
		}
		
		persist();
	}
	
	/**
	 * Poll the stored tokens and expunge those that have expired.
     *
	 * @throws AceException 
	 */
	public synchronized void purgeTokens() 
				throws AceException {
	    HashSet<String> tokenToRemove = new HashSet<>();
		for (Map.Entry<String, Map<Short, CBORObject>> foo 
		        : this.cti2claims.entrySet()) {
		    if (foo.getValue() != null) {
		        CBORObject exp = foo.getValue().get(Constants.EXP);
		        if (exp == null) {
		            continue; //This token never expires
		        }
		        if (!exp.isIntegral()) {
		            throw new AceException(
		                    "Expiration time is in wrong format");
		        }
		        if (this.time.getCurrentTime() > exp.AsInt64()) {
		            tokenToRemove.add(foo.getKey());
				}
			}
		}
		for (String cti : tokenToRemove) {
		    removeToken(cti);
		}
	}
	
	/**
	 * Check if there is a token allowing access.
     *
	 * @param kid  the key identifier used for proof-of-possession.
	 * @param subject  the authenticated subject if there is any, can be null
	 * @param resource  the resource that is accessed
	 * @param action  the RESTful action code.
	 * @param intro  the introspection handler, can be null
	 * @return  1 if there is a token giving access, 0 if there is no token 
	 * for this resource and user,-1 if the existing token(s) do not authorize 
	 * the action requested.
	 * @throws AceException 
	 * @throws IntrospectionException 
	 */
	public int canAccess(String kid, String subject, String resource, 
	        short action, IntrospectionHandler intro) 
			        throws AceException, IntrospectionException {
	    //Expunge expired tokens
	    purgeTokens();
	    
	    //Check if we have tokens for this pop-key
	    if (!this.cti2kid.containsValue(kid)) {
	        return UNAUTHZ; //No tokens for this pop-key
	    }
	    
	    //Collect the token id's of matching tokens
	    Set<String> ctis = new HashSet<>();
	    for (String cti : this.cti2kid.keySet()) {
	        if (this.cti2kid.get(cti).equals(kid)) {
	            ctis.add(cti);
	        }
	    }
	 
	    boolean methodNA = false;   
	    for (String cti : ctis) { //All tokens linked to that pop key
	        //Check if we have the claims for that cti
	        //Get the claims
            Map<Short, CBORObject> claims = this.cti2claims.get(cti);
            if (claims == null || claims.isEmpty()) {
                //No claims found
                continue;
            }
	        
          //Check if the subject matches
            CBORObject subO = claims.get(Constants.SUB);
            if (subO != null) {
                if (subject == null) {
                    //Token requires subject, but none provided
                    continue;
                }
                if (!subO.AsString().equals(subject)) {
                    //Token doesn't match subject
                    continue;
                }
            }
            
            //Check if the token is expired
            CBORObject exp = claims.get(Constants.EXP); 
             if (exp != null && !exp.isIntegral()) {
                    throw new AceException(
                            "Expiration time is in wrong format");
             }
             if (exp != null && exp.AsInt64() < this.time.getCurrentTime()) {
                 //Token is expired
                 continue;
             }
            
             //Check nbf
             CBORObject nbf = claims.get(Constants.NBF);
             if (nbf != null &&  !nbf.isIntegral()) {
                 throw new AceException("NotBefore time is in wrong format");
             }
             if (nbf != null && nbf.AsInt64() > this.time.getCurrentTime()) {
                 //Token not valid yet
                 continue;
             }   
            
	        //Check the scope
             CBORObject scope = claims.get(Constants.SCOPE);
             if (scope == null) {
                 LOGGER.severe("Token: " + cti + " has no scope");
                 throw new AceException("Token: " + cti + " has no scope");
                 
             }
             
             if (this.scopeValidator.scopeMatchResource(scope, resource)) {
                 if (this.scopeValidator.scopeMatch(scope, resource, action)) {
                     //Check if we should introspect this token
                     if (intro != null) {
                         byte[] ctiB = Base64.getDecoder().decode(cti);
                         Map<Short,CBORObject> introspect = intro.getParams(ctiB);
                         if (introspect != null 
                                 && introspect.get(Constants.ACTIVE) == null) {
                             throw new AceException("Token introspection didn't "
                                     + "return an 'active' parameter");
                         }
                         if (introspect != null && introspect.get(
                                 Constants.ACTIVE).isTrue()) {
                             return OK; // Token is active and passed all other tests
                         }
                     } else {
                       //We didn't introspect, but the token is ok otherwise
                         return OK;
                     }
                 }
                 methodNA = true; //scope did match resource but not action
             }
	    }
	    return ((methodNA) ? METHODNA : FORBID); 
	}

	/**
	 * Save the current tokens in a JSON file
	 * @throws AceException 
	 */
	private void persist() throws AceException {
	    JSONArray config = new JSONArray();
	    for (String cti : this.cti2claims.keySet()) {
	        Map<Short, CBORObject> claims = this.cti2claims.get(cti);
	        JSONObject token = new JSONObject();
	        for (Map.Entry<Short,CBORObject> entry : claims.entrySet()) {
	            token.put(entry.getKey().toString(), 
	                    Base64.getEncoder().encodeToString(
	                            entry.getValue().EncodeToBytes()));
	        }
	        config.put(token);
	    }

        try (FileOutputStream fos 
                = new FileOutputStream(this.tokenFile, false)) {
            fos.write(config.toString(4).getBytes(Constants.charset));
            fos.close();
        } catch (JSONException | IOException e) {
            throw new AceException(e.getMessage());
        }
        
	}
	
	/**
	 * Get the proof-of-possession key of a token identified by its 'cti'.
	 * 
	 * @param cti  the cti of the token Base64 encoded
	 * 
	 * @return  the pop-key the token or null if this cti is unknown
	 * @throws AceException 
	 */
	public OneKey getPoP(String cti) throws AceException {
	    if (cti != null) {
	        purgeTokens();
	        String kid = this.cti2kid.get(cti);
	        OneKey key = this.kid2key.get(kid);
	        if (key == null) {
	            LOGGER.finest("Token with cti: " + cti 
	                    + " not found in getPoP()");
	            return null;
	        }
	        return key;
	    }
        LOGGER.severe("getCnf() called with null cti");
        throw new AceException("Must supply non-null cti to get cnf");
	}

	/**
	 * Get a key identified by it's 'kid'.
     * 
     * @param kid  the kid of the key
     * 
     * @return  the key identified by this kid of null if we don't have it
     * 
     * @throws AceException 
     */
	public OneKey getKey(String kid) throws AceException {
        if (kid != null) {
            OneKey key = this.kid2key.get(kid);
            if (key == null) {
                LOGGER.finest("Key with kid: " + kid 
                        + " not found in getKey()");
                return null;
            }
            return key;
        }
        LOGGER.severe("getKey() called with null kid");
        throw new AceException("Must supply non-null kid to get key");     
    }
	
	
	/**
	 * Get the kid by the subject id.
	 * 
	 * @param sid  the subject id
	 * 
	 * @return  the kid this subject uses
	 */
	public String getKid(String sid) {
	    if (sid != null) {
	        return this.sid2kid.get(sid);
	    }
	    LOGGER.finest("Key-Id for Subject-Id: " + sid + " not found");
	    return null;
	}
	
    @Override
    public synchronized void close() throws AceException {
        if (!this.closed) {
            this.closed = true;   
            persist();
            singleton = null;
        }
    }
    
    /**
     * @return  a set of all token ids (cti) stored in this repository
     */
    public Set<String> getCtis() {
        return new HashSet<>(this.cti2claims.keySet());
    }

    /**
     * Checks if a given scope is meaningful for this repository.
     * 
     * @param scope  the Scope can be CBOR String or CBOR array
     * @return true if the scope is meaningful, false otherwise 
     * @throws AceException 
     */
    public boolean checkScope(CBORObject scope) throws AceException {
        return this.scopeValidator.isScopeMeaningful(scope);
    }
    
    /**
     * Returns the necessary scope to perform the given action on the given
     * resource.
     * 
     * @param resource  the resource
     * @param action  the action
     * @return  the scope necessary to perform the action on the resource
     */
    public CBORObject getScope(String resource, short action) {
        return this.scopeValidator.getScope(resource, action);
    }

    /**
     * Create a client-nonce to ensure freshness of access tokens, when the
     * RS has no synchronzied clock with the AS. 
     * 
     * @return  a nonce
     *
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public byte[] createNonce() 
            throws NoSuchAlgorithmException, InvalidKeyException {
        if (this.cnonceCounter == -1) {
            LOGGER.info("cnonce requested but not configured to handle them");
            return null;
        }
        if (this.cnonceCounter == Integer.MAX_VALUE) {
            LOGGER.info("cnonce counter wrapped");
            this.cnonceCounter = 1;
            this.cnonceSeen = 0;
            this.cnonceWindow = 0;
            //Generate a new key to invalidate the old cnonces
            this.cnonceKey = new byte[32];
            new SecureRandom().nextBytes(this.cnonceKey);  
        } 

        byte[] mac = null;
        byte[] counter = ByteBuffer.allocate(4).putInt(
                this.cnonceCounter).array();
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(
                this.cnonceKey, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        mac = sha256_HMAC.doFinal(counter);  
        byte[] nonce = new byte[mac.length + counter.length];
        System.arraycopy(mac,0, nonce, 0, mac.length);
        System.arraycopy(counter, 0, nonce , mac.length, counter.length);
        this.cnonceCounter++;       
        
        
        return nonce;
    }

    /**
     * Checks if a given scope is meaningful for this repository.
     * 
     * @param scope  the Scope can be CBOR String or CBOR array
     * @param aud  the Audiences as an Array of Strings
     * @return true if the scope is meaningful, false otherwise 
     * @throws AceException 
     */
    public boolean checkScope(CBORObject scope, ArrayList<String> aud) throws AceException {
        return this.scopeValidator.isScopeMeaningful(scope, aud);
    }
}

