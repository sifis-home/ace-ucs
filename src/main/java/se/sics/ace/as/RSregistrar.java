package se.sics.ace.as;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This class stores information about the RS that are registered at this AS.
 * 
 * FIXME: Add methods to persist and load these values
 *  
 * @author Ludwig Seitz
 *
 */
public class RSregistrar {
	
	private Map<String, Set<String>> supportedProfiles;
	
	private Map<String, Set<String>> supportedScopes;

	/**
	 * Constructor. Makes an empty registrar
	 */
	public RSregistrar() {
		this.supportedProfiles = new HashMap<>();
		this.supportedScopes = new HashMap<>();
	}
	
	/**
	 * Registers a new RS at this AS.
	 * 
	 * @param rs  the identifier for the RS
	 * @param profiles  the profiles this RS supports
	 * @param scopes  the scopes this RS supports
	 */
	public void addRS(String rs, Set<String> profiles, Set<String> scopes) {
		this.supportedProfiles.put(rs, profiles);
		this.supportedScopes.put(rs, scopes);
	}
	
	/**
	 * Removes an RS from the registry.
	 * 
	 * @param rs  the identifier of the RS
	 */
	public void removeRS(String rs) {
		this.supportedProfiles.remove(rs);
		this.supportedScopes.remove(rs);
	}
	
	
	/**
	 * Checks if the given RS supports the given profile.
	 * 
	 * @param rs  the RS identifier
	 * @param profile  the profile identifier
	 * 
	 * @return  true if the RS supports the profile, false otherwise
	 */
	public boolean isProfileSupported(String rs, String profile) {
		Set<String> profiles = this.supportedProfiles.get(rs);
		if (profiles == null || !profiles.contains(profile)) {
			return false;
		}
		return true;
	}
	
	/**
	 * Checks if the given RS supports the given scope.
	 * 
	 * @param rs  the RS identifier
	 * @param scope  the scope
	 * 
	 * @return  true if the RS supports the scope, false otherwise
	 */
	public boolean isScopeSupported(String rs, String scope) {
		Set<String> scopes = this.supportedScopes.get(rs);
		if (scopes == null || !scopes.contains(scope)) {
			return false;
		}
		return true;
	}
	
}
