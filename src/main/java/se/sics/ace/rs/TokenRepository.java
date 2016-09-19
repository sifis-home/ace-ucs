/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
package se.sics.ace.rs;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.bouncycastle.util.Arrays;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.cwt.CWT;

/**
 * This class is used to store valid access tokens and 
 * provides methods to check them against an incoming request.  It is the 
 * responsibility of the request handler to call this class. 
 * 
 * Note that this class assumes that every token has a 'scope', 'sub', and 
 * 'aud' and in addition every CWT has a 'cti'.  Tokens that don't have these
 * will lead to exceptions.
 *  
 * @author Ludwig Seitz
 *
 */
public class TokenRepository {
	
	private Map<String, Set<String>> resource2scope;
	private Map<String, Set<CWT>> scope2cwt;
	private Map<String, Set<String>> scope2reftoken;
	private Set<String> resources;
	private ScopeValidator scopeValidator;
	
	/**
	 * Creates a new token repository.
	 * 
	 * @param scopeValidator  the application specific scope validator
	 * @param resources  the resources this TokenRepository serves 
	 */
	public TokenRepository(ScopeValidator scopeValidator, 
			Set<String> resources) {
		this.scopeValidator = scopeValidator;
		this.scope2cwt = new HashMap<>();
		this.scope2reftoken = new HashMap<>();
		this.resource2scope = new HashMap<>();
		this.resources = resources;
	}
	
	/**
	 * Add a new resource to the set of resources managed by this repository.
	 * 
	 * @param resourceId  the identifier of the new resource. 
	 * @throws RSException 
	 */
	public void addResource(String resourceId) throws RSException {
		this.resources.add(resourceId);
		Set<String> scopes = new HashSet<>();
		for (String scope : this.scope2cwt.keySet()) {
			if (this.scopeValidator.scopeIncludesResource(scope, resourceId)) {
				scopes.add(scope);
			}
		}
		for (String scope : this.scope2reftoken.keySet()) {
			if (this.scopeValidator.scopeIncludesResource(scope, resourceId)) {
				scopes.add(scope);
			}
		}
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
	 * Add a new CWT to the repo.  Note that this method DOES NOT check
	 * the validity of the token.
	 * 
	 * @param token  The CWT containing the token
	 * @throws RSException 
	 */
	public void addCWT(CWT token) throws RSException {
		CBORObject so = token.getClaim("scope");
		if (so == null) {
			throw new RSException("Token has no scope");
		}
		String scope = so.AsString();

		if (token.getClaim("cti") == null) {
			throw new RSException("Token has no cti");
		}
		
		//Store the mapping scope 2 token
		Set<CWT> cwts = this.scope2cwt.get(scope);
		if (cwts == null) {
			cwts = new HashSet<>();
		}
		cwts.add(token);			
		this.scope2cwt.put(scope, cwts);

		//Store the mapping scope 2 resources
		for (String resource : this.resources) {
			if (this.scopeValidator.scopeIncludesResource(scope, resource)) {
				Set<String> scopes = this.resource2scope.get(resource);
				if (scopes == null) {
					scopes = new HashSet<>();

				}
				scopes.add(scope);
				this.resource2scope.put(resource, scopes);
			}
		}
	}
	
	/**
	 * Add a new reference token to the repo.  
	 * Note that this method DOES NOT check the validity of the token.
	 * 
	 * @param token  the String containing the token-reference
	 * @param parameters  the parameters (claims) of this token
	 * @throws RSException 
	 */
	public void addRefToken(String token, Map<String, CBORObject> parameters)
			throws RSException {
		if (parameters == null) {
			throw new RSException(
					"Need token parameters");
		}
		CBORObject so = parameters.get("scope");
		if (so == null) {
			throw new RSException("Token has no scope");
		}
		String scope = so.AsString();
		
		//Store the mapping scope 2 reftoken
		Set<String> refs = this.scope2reftoken.get(scope);
		if (refs == null) {
			refs = new HashSet<>();
		}
		refs.add(token);			
		this.scope2reftoken.put(scope, refs);

		//Store the mapping scope 2 resources
		for (String resource : this.resources) {
			if (this.scopeValidator.scopeIncludesResource(scope, resource)) {
				Set<String> scopes = this.resource2scope.get(resource);
				if (scopes == null) {
					scopes = new HashSet<>();

				}
				scopes.add(scope);
				this.resource2scope.put(resource, scopes);
			}
		}
	}
	
	
	/**
	 * Remove an existing CWT from the repository.
	 * 
	 * @param  tokenID  the cid of the CWT to be removed.
	 */
	public void removeTokenCid(byte[] tokenID) {
		for(Entry<String, Set<CWT>> foo : this.scope2cwt.entrySet()) {
			for (CWT bar : foo.getValue()) {
				if (Arrays.areEqual(bar.getClaim("cti").EncodeToBytes(), 
						tokenID)) {
					Set<CWT> foobar = this.scope2cwt.get(foo.getKey());
					foobar.remove(bar);
					if (foobar.isEmpty()) {
						this.scope2cwt.remove(foo.getKey());
						//Check if the reftokens are empty too for this scope
						if (!this.scope2reftoken.containsKey(foo.getKey())) {
							removeScope(foo.getKey());
						}
					} else {
						this.scope2cwt.put(foo.getKey(), foobar);
					}
					
				}
			}
		}
	}
	
	private void removeScope(String scope) {
		for (Entry<String, Set<String>> foo : 
				this.resource2scope.entrySet()) {
			if (foo.getValue().contains(scope)) {
				foo.getValue().remove(scope);
				if (foo.getValue().isEmpty()) {
					this.resource2scope.remove(foo.getKey());
				}
			}
		}
	}
	
	/**
	 * Remove a reference token from the repository.
	 * 
	 * @param reftoken  the token to be removed.
	 */
	public void removeRefToken(String reftoken) {
		for(Entry<String, Set<String>> foo : this.scope2reftoken.entrySet()) {
			for (String bar : foo.getValue()) {
				if (bar.equals(reftoken)) {
					Set<String> foobar 
						= this.scope2reftoken.get(foo.getKey());
					foobar.remove(bar);
					if (foobar.isEmpty()) {
						this.scope2reftoken.remove(foo.getKey());
						//Check if the CWTs are empty too for this scope
						if (!this.scope2cwt.containsKey(foo.getKey())) {
							removeScope(foo.getKey());
						}
					} else {
						this.scope2reftoken.put(foo.getKey(), foobar);
					}
					
				}
			}
		}
	}
	
	/**
	 * Poll the stored tokens and expunge those that have expired.
	 * @param time  the time provider
	 * @param intro  the introspection handler
	 * @throws RSException 
	 */
	public void pollTokens(TimeProvider time, IntrospectionHandler intro) 
				throws RSException {
		for (Entry<String, Set<CWT>> foo : this.scope2cwt.entrySet()) {
			for (CWT cwt : foo.getValue()) {
				if (cwt.expired(time.getCurrentTime())) {
					removeTokenCid(cwt.getClaim("cti").GetByteString());
				}
			}
		}
		
		//Now check the reference tokens
		if (intro != null) {
			for (Entry<String, Set<String>> bar 
					: this.scope2reftoken.entrySet()) {
				for (String reft : bar.getValue()) {
					Map<String, CBORObject> claims = intro.getParams(reft);
					if (claims.get("active") == null) {
						throw new RSException("Token introspection didn't "
								+ "return an 'active' parameter");
					}
					if (!claims.get("active").AsBoolean()) {
						removeRefToken(reft);
					} else {
						CBORObject expO = claims.get("exp");
						if (expO != null) {
							if (time.getCurrentTime() > expO.AsInt64()) {
								//	Remove expired token
								removeRefToken(reft);
							}
						}
					}
				}
			}
		}
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
	 * @throws RSException 
	 */
	public boolean canAccess(String subject, String resource, String action, 
			TimeProvider time, IntrospectionHandler intro) throws RSException {
		//Check if we have a token that is in scope for this resource
		for (String scope : this.resource2scope.get(resource)) {
			//Check if the action matches
			if (!this.scopeValidator.scopeIncludesAction(scope, action)) {
				//Action does not match this scope
				continue;
			}
			for (CWT token : this.scope2cwt.get(scope)) {
				//Check if the subject matches
				CBORObject subO = token.getClaim("sub");
				if (subO == null) {
					throw new RSException("Token has no 'sub' claim");
				}
				if (!subO.AsString().equals(subject)) {
					//Token doesn't match subject
					continue;
				}
				if (!token.isValid(time.getCurrentTime())) {
					//token expired or not valid yet
					continue;
				}
				//Check if we should introspect this CWT
				if (intro != null) {
					Map<String,CBORObject> introspect = intro.getParams(
							token.getClaim("cti").AsString());
					if (introspect.get("active") == null) {
						throw new RSException("Token introspection didn't "
								+ "return an 'active' parameter");
					}
					if (introspect.get("active").AsBoolean()) {
						return true;
					}
				} else { //We didn't introspect but everything else checked out
					return true;
				}
			}

			//Now check reference tokens
			if (intro != null) {
				for (String reftoken : this.scope2reftoken.get(scope)) {
					Map<String, CBORObject> claims = intro.getParams(reftoken);
					//Check valid
					if (!claims.get("active").AsBoolean()) {
						continue;
					}

					//Check if the subject matches
					CBORObject subO = claims.get("sub");
					if (subO == null) {
						throw new RSException(
								"Introspection gave no 'sub' parameter");
					}
					if (!subO.AsString().equals(subject)) {
						//Token doesn't match subject
						continue;
					}
					
					//Check nbf and exp for the found match
					CBORObject nbfO = claims.get("nbf");
					if (nbfO != null &&  nbfO.AsInt64() 
							> time.getCurrentTime()) {
						//Token not valid yet
						continue;
					}	
					CBORObject expO = claims.get("exp");
					if (expO != null && expO.AsInt64() < 
							time.getCurrentTime()) {
						//Token has expired
						continue;
					}		
				}
			}
		}
		
		//No matching token found
		return false;
	}
	
	/**
	 * Checks if this scope applies to any resource.
	 * @param scope  the scope
	 * @return  true if the scope applies to any resource, false if not
	 * @throws RSException 
	 */
	public boolean inScope(String scope) throws RSException {
		for (String resource : this.resources) {
			if (this.scopeValidator.scopeIncludesResource(scope, resource)) {
				return true;
			}
		}
		return false;
	}
}
