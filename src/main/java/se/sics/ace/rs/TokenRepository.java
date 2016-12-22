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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;

/**
 * This class is used to store valid access tokens and 
 * provides methods to check them against an incoming request.  It is the 
 * responsibility of the request handler to call this class. 
 * 
 * Note that this class assumes that every token has a 'scope', 'sub',  
 * 'aud' and 'cti' (the token itself for a reference token).  Tokens that 
 * don't have these will lead to request failure.
 *  
 * @author Ludwig Seitz
 *
 */
public class TokenRepository {
	
    /**
     * Maps resource identifiers to matching scopes.
     */
	private Map<String, Set<String>> resource2scope;
	
	/**
	 * Maps scopes to token identifiers (cti).
	 */
	private Map<String, Set<String>> scope2cti;
	
	/**
	 * Maps cti to the claims of the corresponding token
	 */
	private Map<String, Map<String,CBORObject>> cti2claims;
	
	/**
	 * The resources handled by this repository
	 */
	private Set<String> resources;
	
	/**
	 * The scope validator
	 */
	private ScopeValidator scopeValidator;
	
	/**
	 * The filename + path for the JSCON file in which the tokens are stored
	 */
	private String tokenFile;
	
	/**
	 * Creates a new token repository and loads the existing tokens
	 * from a JSON file is there is one.
	 * 
	 * The JSON file stores the tokens as a JSON array of JSON maps,
	 * where each map represents the claims of a token, String mapped to
	 * the Base64 encoded byte representation of the CBORObject.
	 * 
	 * @param scopeValidator  the application specific scope validator
	 * @param resources  the resources this TokenRepository serves 
	 * @param tokenFile  the file storing the existing tokens, if the file
	 *     does not exist it is created
	 * @throws IOException 
	 * @throws AceException 
	 */
	public TokenRepository(ScopeValidator scopeValidator, 
			Set<String> resources, String tokenFile) 
			        throws IOException, AceException {
	    this.resource2scope = new HashMap<>();
	    this.scope2cti = new HashMap<>();
	    this.cti2claims = new HashMap<>();
	    this.resources = new HashSet<>(resources);
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
                this.addToken(params);
            }
        }
	}
	
	/**
	 * Add a new resource to the set of resources managed by this repository.
	 * 
	 * @param resourceId  the identifier of the new resource. 
	 * @throws AceException 
	 */
	public void addResource(String resourceId) throws AceException {
		//Fetch all matching scopes
		Set<String> scopes = new HashSet<>();
		for (String scope : this.scope2cti.keySet()) {
			if (this.scopeValidator.scopeMatchResource(scope, resourceId)) {
				scopes.add(scope);
			}
		}
		//Add the matching scopes to the map.
		this.resource2scope.put(resourceId, scopes);
	}
	
	/**
	 * Remove an existing resource from the set of managed resources.
	 * 
	 * @param resourceId  the identifier of the resource to be removed.
	 */
	public void removeResource(String resourceId) {
		this.resources.remove(resourceId);
		this.resource2scope.remove(resourceId);
	}
	
	/**
	 * Add a new Access Token to the repo.  Note that this method DOES NOT 
	 * check the validity of the token.
	 * 
	 * @param claims  the claims of the token
	 * @throws AceException 
	 */
	public void addToken(Map<String, CBORObject> claims) throws AceException {
		CBORObject so = claims.get("scope");
		if (so == null) {
			throw new AceException("Token has no scope");
		}
		String scope = so.AsString();

		CBORObject cticb = claims.get("cti");
		if (cticb == null) {
			throw new AceException("Token has no cti");
		} else if (!cticb.getType().equals(CBORType.ByteString)) {
		    throw new AceException("Cti has invalid format");
		}
		
		String cti = new String(claims.get("cti").GetByteString());
		
		String[] scopes = scope.split(" ");
		
		//Store the mapping scope 2 cti
		for (int i=0; i<scopes.length; i++) {
		    Set<String> ctis = this.scope2cti.get(scopes[i]);
		    if (ctis == null) {
		        ctis = new HashSet<>();
		    }
		    ctis.add(cti);
		    this.scope2cti.put(scopes[i], ctis);
		    
	        //Store the mapping resource 2 scope
	        for (String resource : this.resources) {
	            if (this.scopeValidator.scopeMatchResource(scopes[i], resource)) {
	                Set<String> rscope = this.resource2scope.get(resource);
	                if (rscope == null) {
	                    rscope = new HashSet<>();

	                }
	                rscope.add(scopes[i]);
	                this.resource2scope.put(resource, rscope);
	            }
	        }
	        persist();
		}
		
		//Store the mapping cti 2 claims, if a token with the same cti
		//already exists, this leads to an exception
		if (this.cti2claims.containsKey(cti)) {
		    throw new AceException("Duplicate token identifier");
		}

		this.cti2claims.put(cti, claims);

		
	}

	/**
	 * Remove an existing token from the repository.
	 * 
	 * @param cti  the cti of the token to be removed.
	 * @throws AceException 
	 */
	public void removeToken(CBORObject cti) throws AceException {
	    if (cti == null) {
            throw new AceException("Cti is null");
        } else if (!cti.getType().equals(CBORType.ByteString)) {
            throw new AceException("Cti has invalid format");
        }
        
        String ctiStr = new String(cti.GetByteString());
        this.cti2claims.remove(ctiStr);
        Set<String> removableScopes = new HashSet<>();
		for(Entry<String, Set<String>> foo : this.scope2cti.entrySet()) {
		    if (foo.getValue() == null) {
		        removableScopes.add(foo.getKey());
		    } else {
		        foo.getValue().remove(ctiStr);
		        if (foo.getValue().isEmpty()) {
		            removableScopes.add(foo.getKey());
		        }
			}
		}
		
		//Now remove the empty scopes
		for (String scope : removableScopes) {
		    this.scope2cti.remove(scope);
		}
		
		//Now clean the resource 2 scope mappings
		for (Entry<String, Set<String>> foo : this.scope2cti.entrySet()) {
		    if (foo.getValue() == null || foo.getValue().isEmpty()) {
		        this.resource2scope.remove(foo.getKey());		        
		    }
		}
		persist();
	}
	
	/**
	 * Poll the stored tokens and expunge those that have expired.
	 * @param time  the time provider
     *
	 * @throws AceException 
	 */
	public void pollTokens(TimeProvider time) 
				throws AceException {
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
					removeToken(foo.getValue().get("cti"));
				}
			}
		}
		persist();
	}
	
	/**
	 * Check if there is a token allowing access.
	 * 
	 * @param subject  the authenticated subject.
	 * @param resource  the resource that is accessed
	 * @param action  the RESTful action on that resource
	 * @param time  the time provider
	 * @param intro  the introspection handler, can be null
	 * @return  true if the subject can access the resource 
	 * 	with the given action, false if not.
	 * @throws AceException 
	 */
	public boolean canAccess(String subject, String resource, String action, 
			TimeProvider time, IntrospectionHandler intro) 
			        throws AceException {
		//Check if we have a token that is in scope for this resource
		for (String scope : this.resource2scope.get(resource)) {
			//Check if the scope matches
			if (!this.scopeValidator.scopeMatch(scope, resource, action)) {
				//Action does not match this scope, net iteration
				continue;
			}
			for (String cti : this.scope2cti.get(scope)) {
			    //Get the claims
			    Map<String, CBORObject> claims = this.cti2claims.get(cti);
			    if (claims == null || claims.isEmpty()) {
			        //No claims found
			        continue;
			    }
			    
				//Check if the subject matches
				CBORObject subO = claims.get("sub");
				if (subO == null) {
					throw new AceException("Token has no 'sub' claim");
				}
				if (!subO.AsString().equals(subject)) {
					//Token doesn't match subject
					continue;
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

				//Check if we should introspect this token
				if (intro != null) {
				    Map<String,CBORObject> introspect = intro.getParams(cti);
					if (introspect != null && introspect.get("active") == null) {
						throw new AceException("Token introspection didn't "
								+ "return an 'active' parameter");
					}
					if (introspect != null && introspect.get("active").isTrue()) {
						return true;
					}
				} else { //We didn't introspect but everything else checked out
					return true;
				}
			}
		}
		
		//No matching token found
		return false;
	}
	
	/**
	 * Checks if this scope applies to any resource.
	 * 
	 * @param scope  the scope
	 * @return  true if the scope applies to any resource, false if not
	 * @throws AceException 
	 */
	public boolean inScope(String scope) throws AceException {
		for (String resource : this.resources) {
			if (this.scopeValidator.scopeMatchResource(scope, resource)) {
				return true;
			}
		}
		return false;
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
            fos.write(config.toString(4).getBytes());
        } catch (JSONException | IOException e) {
            throw new AceException(e.getMessage());
        }
	}
}
