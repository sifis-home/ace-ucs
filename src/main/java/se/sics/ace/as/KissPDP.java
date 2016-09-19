package se.sics.ace.as;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A simple PDP implementation for test purposes. Uses static ACLs for everything.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissPDP implements PDP {

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
	 * Note that this storage assumes that scopes are split by whitespace.
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
		Set<String> scopes = clientACL.get(aud);
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
