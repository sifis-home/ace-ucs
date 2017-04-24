/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
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
 * Map as local cti.
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
     * Return codes of the canAccess() method
     */
    
    /**
     * Return codes of the canAccess() method
     */
    
    
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
	 * Maps cti to the claims of the corresponding token
	 */
	private Map<String, Map<String, CBORObject>> cti2claims;
	
	
	/**
	 * Map key identifiers collected from the access tokens to keys
	 */
	protected Map<String, OneKey> kid2key;
	
	/**
	 * Map the  token identifier to the corresponding pop-key kid
	 */
	protected Map<String, String>cti2kid;
	
	/**
	 * The scope validator
	 */
	private ScopeValidator scopeValidator;
	
	/**
	 * The filename + path for the JSON file in which the tokens are stored
	 */
	private String tokenFile;

	
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
	 * @param scopeValidator
	 * @param tokenFile
	 * @param ctx
	 * @throws AceException
	 * @throws IOException
	 */
	public static void create(ScopeValidator scopeValidator, 
            String tokenFile, CwtCryptoCtx ctx) 
                    throws AceException, IOException {
	    if (singleton != null) {
	        throw new AceException("Token repository already exists");
	    }
	    singleton = new TokenRepository(scopeValidator, tokenFile, ctx);
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
	 * @throws IOException 
	 * @throws AceException 
	 */
	protected TokenRepository(ScopeValidator scopeValidator, 
	        String tokenFile, CwtCryptoCtx ctx) 
			        throws IOException, AceException {
	    this.closed = false;
	    this.cti2claims = new HashMap<>();
	    this.kid2key = new HashMap<>();
	    this.cti2kid = new HashMap<>();
	    this.scopeValidator = scopeValidator;
	    if (tokenFile == null) {
	        throw new IllegalArgumentException("Must provide a token file path");
	    }
	    this.tokenFile = tokenFile;
	    File f = new File(this.tokenFile);
	    if (!f.exists()) {
	        return; //File will be created if tokens are added
	    }
	    FileInputStream fis = new FileInputStream(f);
        Scanner scanner = new Scanner(fis, "UTF-8" );
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
                Map<String, CBORObject> params = new HashMap<>();
                while (iterToken.hasNext()) {
                    String key = iterToken.next();  
                    params.put(key, CBORObject.DecodeFromBytes(
                            Base64.getDecoder().decode(
                                    token.getString((key)))));
                }
                this.addToken(params, ctx);
            }
        }
	}

	/**
	 * Add a new Access Token to the repo.  Note that this method DOES NOT 
	 * check the validity of the token.
	 * 
	 * @param claims  the claims of the token
	 * @param ctx  the crypto context of this RS  
	 * 
	 * @return  the cti or the local id given to this token
	 * 
	 * @throws AceException 
	 * @throws CoseException 
	 */
	public synchronized CBORObject addToken(Map<String, CBORObject> claims, 
	        CwtCryptoCtx ctx) throws AceException {
		CBORObject so = claims.get("scope");
		if (so == null) {
			throw new AceException("Token has no scope");
		}

		CBORObject cticb = claims.get("cti");
		String cti = null;
		if (cticb == null) {
			cti = String.valueOf(claims.hashCode());
		} else if (!cticb.getType().equals(CBORType.ByteString)) {
		    LOGGER.info("Token's cti in not a ByteString");
            throw new AceException("Cti has invalid format");
        } else {		
		    cti = new String(claims.get("cti").GetByteString());
		}
		
		//Check for duplicate cti
		if (this.cti2claims.containsKey(cti)) {
		    throw new AceException("Duplicate cti");
		}

		//Need deep copy here
		Map<String, CBORObject> foo = new HashMap<>();
		foo.putAll(claims);
		this.cti2claims.put(cti, foo);

		//Store the pop-key
		CBORObject cnf = claims.get("cnf");
        if (cnf == null) {
            throw new AceException("Token has no cnf");
        } 
        if (cnf.getType().equals(CBORType.Map)) {
            //This is either a kid or a COSE_Key
            String kid = fetchKid(cnf);
            if (cnf.size() == 1) {//This is a kid only
                if (!this.kid2key.containsKey(kid)) {
                    LOGGER.info("Token refers to unknown kid");
                    throw new AceException("Token refers to unknown kid");
                }
                //Store the association between token and known key
                this.cti2kid.put(cti, kid);  
            } else { //This should be a COSE_Key
                try {
                    OneKey key = new OneKey(cnf);
                    this.cti2kid.put(cti, kid);
                    this.kid2key.put(kid, key);
                } catch (CoseException e) {
                    LOGGER.severe("Error while parsing cnf element: " 
                            + e.getMessage());
                    throw new AceException("Invalid cnf element: " 
                            + e.getMessage());
                }
            }
        } else { //assume this is a COSE Encrypt0
            Encrypt0Message msg = new Encrypt0Message();
            try {
                msg.DecodeFromCBORObject(cnf);
                msg.decrypt(ctx.getKey());
                CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
                OneKey key = new OneKey(keyData);
                String kid = fetchKid(keyData);
                this.cti2kid.put(cti, kid);
                this.kid2key.put(kid, key);
            } catch (CoseException | InvalidCipherTextException e) {
                LOGGER.severe("Error while decrypting a cnf claim: "
                        + e.getMessage());
                throw new AceException("Error while decrypting a cnf claim");
            }
        }  
        
        return CBORObject.FromObject(cti.getBytes());
	}
	
	/**
	 * Fetch the kid from a cnf element in a token.
	 * 
	 * @param cnf  the cnf element
	 * 
	 * @return the String representation of the kid
	 * 
	 * @throws AceException
	 */
	private static String fetchKid(CBORObject cnf) throws AceException {
	    CBORObject kid = cnf.get("kid"); //Unabbreviated
        if (kid == null) {
            kid = cnf.get(KeyKeys.KeyId.AsCBOR()); //Abbreviated 
            if (kid == null) {
                LOGGER.severe("kid not found in cnf claim");
                throw new AceException("Cnf claim is missing kid");
            }
        }
        if (kid.getType().equals(CBORType.ByteString)) {
            //Note that kid bytes my not be generated from a String
           return new String(kid.GetByteString());
        }
        LOGGER.severe("kid is not a byte string");
        throw new AceException("cnf contains invalid kid");
	}

	/**
	 * Remove an existing token from the repository.
	 * 
	 * @param cti  the cti of the token to be removed.
	 * @throws AceException 
	 */
	public synchronized void removeToken(CBORObject cti) throws AceException {
	    if (cti == null) {
            throw new AceException("Cti is null");
        } else if (!cti.getType().equals(CBORType.ByteString)) {
            throw new AceException("Cti has invalid format");
        }
        
        String ctiStr = new String(cti.GetByteString());
        
        //Remove the claims
        this.cti2claims.remove(ctiStr);
 
		//Remove the mapping to the pop key
		this.cti2kid.remove(ctiStr);
		
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
	 * @param time  the time provider
     *
	 * @throws AceException 
	 */
	public synchronized void pollTokens(TimeProvider time) 
				throws AceException {
	    HashSet<CBORObject> tokenToRemove = new HashSet<>();
		for (Entry<String, Map<String, CBORObject>> foo 
		        : this.cti2claims.entrySet()) {
		    if (foo.getValue() != null) {
		        CBORObject exp = foo.getValue().get("exp");
		        if (exp == null) {
		            continue; //This token never expires
		        }
		        if (!exp.isIntegral()) {
		            throw new AceException("Expiration time is in wrong format");
		        }
		        if (exp.AsInt64() > time.getCurrentTime()) {
		            tokenToRemove.add(foo.getValue().get("cti"));
				}
			}
		}
		for (CBORObject cti : tokenToRemove) {
		    removeToken(cti);
		}
		persist();
	}
	
	/**
	 * Check if there is a token allowing access.
     *
	 * @param kid  the key identifier used for proof-of-possession.
	 * @param subject  the authenticated subject if there is any, can be null
	 * @param resource  the resource that is accessed
	 * @param action  the RESTful action on that resource
	 * @param time  the time provider
	 * @param intro  the introspection handler, can be null
	 * @return  1 if there is a token giving access, 0 if there is no token 
	 * for this resource and user,-1 if the existing token(s) do not authorize 
	 * the action requested.
	 * @throws AceException 
	 */
	public int canAccess(String kid, String subject, String resource, 
	        String action, TimeProvider time, IntrospectionHandler intro) 
			        throws AceException {
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
            Map<String, CBORObject> claims = this.cti2claims.get(cti);
            if (claims == null || claims.isEmpty()) {
                //No claims found
                continue;
            }
	        
          //Check if the subject matches
            CBORObject subO = claims.get("sub");
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
            CBORObject exp = claims.get("exp"); 
             if (exp != null && !exp.isIntegral()) {
                    throw new AceException("Expiration time is in wrong format");
             }
             if (exp != null && exp.AsInt64() < time.getCurrentTime()) {
                 //Token is expired
                 continue;
             }
            
             //Check nbf
             CBORObject nbf = claims.get("nbf");
             if (nbf != null &&  !nbf.isIntegral()) {
                 throw new AceException("NotBefore time is in wrong format");
             }
             if (nbf != null && nbf.AsInt64() > time.getCurrentTime()) {
                 //Token not valid yet
                 continue;
             }   
            
	        //Check the scope
             CBORObject scope = claims.get("scope");
             if (scope == null) {
                 LOGGER.severe("Token: " + cti + " has no scope");
                 throw new AceException("Token: " + cti + " has no scope");
                 
             }
             
             String[] scopes = scope.AsString().split(" ");
             for (String subscope : scopes) {
                 if (this.scopeValidator.scopeMatchResource(subscope, resource)) {
                     if (this.scopeValidator.scopeMatch(subscope, resource, action)) {
                       //Check if we should introspect this token
                         if (intro != null) {
                             Map<String,CBORObject> introspect = intro.getParams(cti);
                             if (introspect != null && introspect.get("active") == null) {
                                 throw new AceException("Token introspection didn't "
                                         + "return an 'active' parameter");
                             }
                             if (introspect != null && introspect.get("active").isTrue()) {
                                 return OK; // Token is active and passed all other tests
                             }

                         }
                        return OK; //We didn't introspect, but the token is ok otherwise
                     }
                    methodNA = true; //scope did match resource but not action
                 }
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
	        Map<String, CBORObject> claims = this.cti2claims.get(cti);
	        JSONObject token = new JSONObject();
	        for (Entry<String,CBORObject> entry : claims.entrySet()) {
	            token.put(entry.getKey(), 
	                    Base64.getEncoder().encodeToString(
	                            entry.getValue().EncodeToBytes()));
	        }
	        config.put(token);
	    }

        try (FileOutputStream fos 
                = new FileOutputStream(this.tokenFile, false)) {
            fos.write(config.toString(4).getBytes(Constants.charset));
        } catch (JSONException | IOException e) {
            throw new AceException(e.getMessage());
        }
	}
	
	/**
	 * Get the proof-of-possession key of a token identified by its 'cti'.
	 * 
	 * @param cti  the cti of the token
	 * 
	 * @return  the pop-key the token or null if this cti is unknown
	 * @throws AceException 
	 */
	public OneKey getPoP(String cti) throws AceException {
	    if (cti != null) {
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
	
    @Override
    public synchronized void close() throws AceException {
        if (!this.closed) {
            this.closed = true;   
            persist();
        }
    }

    
}

