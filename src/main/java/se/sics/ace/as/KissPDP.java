package se.sics.ace.as;

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

/**
 * A simple PDP implementation for test purposes. Uses static ACLs for everything.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissPDP implements PDP {

	/**
	 * @param configurationFile  the file containing the PDP configuration in 
	 * JSON format.
	 * @return  the PDP
	 * @throws PDPException 
	 * @throws IOException 
	 */
	public static KissPDP getInstance(String configurationFile) 
				throws PDPException, IOException {
		FileInputStream fs = new FileInputStream(configurationFile);
		JSONTokener parser = new JSONTokener(fs);
		JSONArray config = new JSONArray(parser);
		
		//Parse the clients allowed to access this AS
		if (!(config.get(0) instanceof JSONArray)) {
			fs.close();
			throw new PDPException("Invalid PDP configuration");
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
				throw new PDPException("Invalid PDP configuration");
			}
		}
		
		//Parse the RS allowed to access this AS
		if (!(config.get(1) instanceof JSONArray)) {
			fs.close();
			throw new PDPException("Invalid PDP configuration");
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
				throw new PDPException("Invalid PDP configuration");
			}
		}
		
		//Read the acl
		if (!(config.get(2) instanceof JSONObject)) {
			fs.close();
			throw new PDPException("Invalid PDP configuration");
		}
		JSONObject aclJ = (JSONObject)config.get(2);
		Map<String, Map<String, Set<String>>> acl = new HashMap<>();
		Iterator<String> clientACL = aclJ.keys();
		//Iterate through the client_ids
		while(clientACL.hasNext()) {
			String client = clientACL.next();
			if (!(aclJ.get(client) instanceof JSONObject)) {
				fs.close();
				throw new PDPException("Invalid PDP configuration");
			}
			Map<String, Set<String>> audM = new HashMap<>(); 
			JSONObject audJ = (JSONObject) aclJ.get(client);
			Iterator<String> audACL = audJ.keys();
			//Iterate through the audiences
			while(audACL.hasNext()) {
				String aud = audACL.next();
				if (!(audJ.get(aud) instanceof JSONArray)) {
					fs.close();
					throw new PDPException("Invalid PDP configuration");
				}
				Set<String> scopeS = new HashSet<>();
				JSONArray scopes = (JSONArray)audJ.get(aud);
				Iterator<Object> scopeI = scopes.iterator();
				//Iterate through the scopes
				while (scopeI.hasNext()) {
					Object scope = scopeI.next();
					if (!(scope instanceof String)) {
						fs.close();
						throw new PDPException("Invalid PDP configuration");
					}
					scopeS.add((String)scope);				
				}
				audM.put(aud, scopeS);
			}
			acl.put(client, audM);
		}
		fs.close();
		return new KissPDP(clients, rs, acl);
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
	 */
	public KissPDP(Set<String> clients, Set<String> rs, 
			Map<String, Map<String,Set<String>>> acl) {
		this.clients = new HashSet<>();
		this.clients.addAll(clients);
		this.rs = new HashSet<>();
		this.rs.addAll(rs);
		this.acl = new HashMap<>();
		this.acl.putAll(acl);
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
	public boolean canAccess(String clientId, String aud, String scope) {
		Map<String,Set<String>> clientACL = this.acl.get(clientId);
		if (clientACL == null || clientACL.isEmpty()) {
			return false;
		}
		Set<String> scopes = clientACL.get(aud);
		if (scopes == null || scopes.isEmpty()) {
			return false;
		}
		String[] requestedScopes = scope.split(" ");
		for (int i=0; i<requestedScopes.length; i++) {
			if (!scopes.contains(requestedScopes[i])) {
				return false;
			}
		}
		//all scopes found
		return true;
	}

}
