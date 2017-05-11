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
package se.sics.ace.examples;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.PDP;

/**
 * A simple PDP implementation for test purposes. Uses static ACLs for everything.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissPDP implements PDP, AutoCloseable {

    private DBConnector db = null;
    
	/**
	 * @param configurationFile  the file containing the PDP configuration in 
	 * JSON format.
	 * @param db  the database connector
	 * @return  the PDP
	 * @throws AceException 
	 * @throws IOException 
	 */
	public static KissPDP getInstance(String configurationFile, DBConnector db) 
				throws AceException, IOException {
		FileInputStream fs = new FileInputStream(configurationFile);
		JSONTokener parser = new JSONTokener(fs);
		JSONArray config = new JSONArray(parser);
		
		//Parse the clients allowed to access this AS
		if (!(config.get(0) instanceof JSONArray)) {
			fs.close();
			throw new AceException("Invalid PDP configuration");
		}		
		JSONArray clientsJ = (JSONArray)config.get(0);
		Set<String> clients = new HashSet<>();
		Iterator<Object> it = clientsJ.iterator();
		while (it.hasNext()) {
			Object next = it.next();
			if (next instanceof String) {
				clients.add((String)next);
			} else {
				fs.close();
				throw new AceException("Invalid PDP configuration");
			}
		}
		
		//Parse the RS allowed to access this AS
		if (!(config.get(1) instanceof JSONArray)) {
			fs.close();
			throw new AceException("Invalid PDP configuration");
		}
		JSONArray rsJ = (JSONArray)config.get(1);
		Set<String> rs = new HashSet<>();
		it = rsJ.iterator();
		while (it.hasNext()) {
			Object next = it.next();
			if (next instanceof String) {
				rs.add((String)next);
			} else {
				fs.close();
				throw new AceException("Invalid PDP configuration");
			}
		}
		
		//Read the acl
		if (!(config.get(2) instanceof JSONObject)) {
			fs.close();
			throw new AceException("Invalid PDP configuration");
		}
		JSONObject aclJ = (JSONObject)config.get(2);
		Map<String, Map<String, Set<String>>> acl = new HashMap<>();
		Iterator<String> clientACL = aclJ.keys();
		//Iterate through the client_ids
		while(clientACL.hasNext()) {
			String client = clientACL.next();
			if (!(aclJ.get(client) instanceof JSONObject)) {
				fs.close();
				throw new AceException("Invalid PDP configuration");
			}
			Map<String, Set<String>> audM = new HashMap<>(); 
			JSONObject audJ = (JSONObject) aclJ.get(client);
			Iterator<String> audACL = audJ.keys();
			//Iterate through the audiences
			while(audACL.hasNext()) {
				String aud = audACL.next();
				if (!(audJ.get(aud) instanceof JSONArray)) {
					fs.close();
					throw new AceException("Invalid PDP configuration");
				}
				Set<String> scopeS = new HashSet<>();
				JSONArray scopes = (JSONArray)audJ.get(aud);
				Iterator<Object> scopeI = scopes.iterator();
				//Iterate through the scopes
				while (scopeI.hasNext()) {
					Object scope = scopeI.next();
					if (!(scope instanceof String)) {
						fs.close();
						throw new AceException("Invalid PDP configuration");
					}
					scopeS.add((String)scope);				
				}
				audM.put(aud, scopeS);
			}
			acl.put(client, audM);
		}
		fs.close();
		return new KissPDP(clients, rs, acl, db);
	}
	
	/**
	 * The identifiers of the clients allowed to submit requests to /token
	 */
	private Set<String> clients;
	
	/**
	 * The identifiers of the resource servers allowed to submit requests to 
	 * /introspect
	 */
	private Set<String> rs;
	
	/**
	 * Maps identifiers of client to a map that maps the audiences they may 
	 * access to the scopes they may access for these audiences.
	 *
	 * Note that this storage assumes that scopes are split by whitespace as
	 * per the standard's specification.
	 */
	private Map<String, Map<String, Set<String>>> acl;
	
	/**
	 * Constructor.
	 * 
	 * @param clients  the clients authorized to make requests to /token
	 * @param rs  the RSs authorized to make requests to /introspect
	 * @param acl   the access tokens clients can request. This maps
	 * 	clientId to a map of audiences to a set of scopes. Where the scopes
	 * 	are split up by whitespace (e.g. a scope of "r_basicprofile 
	 * r_emailaddress rw_groups w_messages" would become four scopes 
	 * "r_basicprofile", "r_emailaddress", "rw_groups" and "w_messages".
	 * @param db  the database connector.
	 */
	public KissPDP(Set<String> clients,
			Set<String> rs,	Map<String, Map<String,Set<String>>> acl,
			DBConnector db) {
		this.clients = new HashSet<>();
		this.clients.addAll(clients);
		this.rs = new HashSet<>();
		this.rs.addAll(rs);
		this.acl = new HashMap<>();
		this.acl.putAll(acl);
		this.db = db;
	}
	
	@Override
	public boolean canAccessToken(String clientId) {
		return this.clients.contains(clientId);
	}

	@Override
	public boolean canAccessIntrospect(String rsId) {
		return this.rs.contains(rsId);
	}

	@Override
	public String canAccess(String clientId, String aud, String scope) 
				throws AceException {
		Map<String,Set<String>> clientACL = this.acl.get(clientId);
		if (clientACL == null || clientACL.isEmpty()) {
			return null;
		}

		Set<String> scopes = null;
		Set<String> rss = this.db.getRSS(aud);
		if (rss == null) {
		    return null;
		}
		for (String rs : rss) {
		    if (scopes == null) {
		        scopes = new HashSet<>();
		        Set<String> bar = clientACL.get(rs);
		        if (bar != null) {
		            scopes.addAll(bar);
		        }
		    } else {
		        Set<String> remains = new HashSet<>(scopes);
		        for (String foo : scopes) {
		            if (clientACL.get(rs) == null ) { 
		                //The client can access nothing on this RS
		                return null;
		            }
		            if (!clientACL.get(rs).contains(foo)) {
		                remains.remove(foo);
		            }
		        }
		        scopes = remains;
		    }
		}
		   
		if (scopes == null || scopes.isEmpty()) {
			return null;
		}
		
		String scopeStr = scope;
		String[] requestedScopes = scopeStr.split(" ");
		String grantedScopes = "";
		for (int i=0; i<requestedScopes.length; i++) {
			if (scopes.contains(requestedScopes[i])) {
				if (!grantedScopes.isEmpty()) {
					grantedScopes += " ";
				}
				grantedScopes += requestedScopes[i];
			}
		}
		//all scopes found
		if (grantedScopes.isEmpty()) {
			return null;
		}
		return grantedScopes;
	}

    @Override
    public void close() throws Exception {
       this.db.close();
    }

}
