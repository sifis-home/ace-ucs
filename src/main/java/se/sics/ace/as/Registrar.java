package se.sics.ace.as;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * This class stores information about the clients and RS that are registered at this AS.
 *  
 * @author Ludwig Seitz
 *
 */
public class Registrar {
	
	
	private static int PROFILES = 0;
	private static int KEYTYPES = 1;
	private static int SCOPES = 2;
	private static int AUDS = 3;
	private static int DEFAUD = 4;
	private static int DEFSCOPE = 5;
	
	/**
	 * The file for persisting the values of this registrar
	 */
	private String configfile;
	
	/**
	 * Identifies the profiles a device supports
	 */
	private Map<String, Set<String>> supportedProfiles;
	
	/**
	 * Identifies the key types (symmetric, asymmetric) a device supports
	 */
	private Map<String, Set<String>> supportedKeyTypes;
	
	/**
	 * Identifies the scopes an RS supports
	 */
	private Map<String, Set<String>> supportedScopes;
	
	/**
	 * Identifies the audiences an RS identifies with
	 */
	private Map<String, Set<String>> rs2aud;
	
	/**
	 * The RS that identify with a specific audience 
	 */
	private Map<String, Set<String>> aud2rs;
	
	/**
	 * Default audience a client uses when requesting a token
	 */
	private Map<String, String> defaultAud;
	
	/**
	 * Default scope a client uses when requesting a token
	 */
	private Map<String, String> defaultScope;

	/**
	 * Constructor. Makes an empty registrar
	 * @throws IOException 
	 */
	public Registrar(String configfile) throws IOException {
		this.configfile = configfile;
		this.supportedProfiles = new HashMap<>();
		this.supportedScopes = new HashMap<>();
		this.rs2aud = new HashMap<>();
		this.supportedKeyTypes = new HashMap<>();
		this.defaultAud = new HashMap<>();
		this.defaultScope = new HashMap<>();
		this.aud2rs = new HashMap<>();
		load();
	}

	/**
	 * Registers a new RS at this AS.
	 * 
	 * @param rs  the identifier for the RS
	 * @param profiles  the profiles this RS supports
	 * @param scopes  the scopes this RS supports
	 * @throws IOException 
	 */
	public void addRS(String rs, Set<String> profiles, Set<String> scopes, 
			Set<String> auds, Set<String> keyTypes) throws IOException {
		this.supportedProfiles.put(rs, profiles);
		this.supportedScopes.put(rs, scopes);
		this.supportedKeyTypes.put(rs, keyTypes);
		this.rs2aud.put(rs, auds);
		for (String aud : auds) {
			Set<String> rss = this.aud2rs.get(aud);
			if (rss == null) {
				rss = new HashSet<String>();
			}
			rss.add(rs);
			this.aud2rs.put(aud, rss);
		}
		persist();	
	}
	
	/**
	 * Registers a new client at this AS.
	 * 
	 * @param client  the identifier for the client
	 * @param profiles  the profiles this client supports
	 * @param defaultScope  the default scope if any, or null
	 * @param defaultAud  the default audience if any, or null
	 * @param keyTypes  the key types this client supports
	 * @throws IOException 
	 */
	public void addClient(String client, Set<String> profiles, String defaultScope, 
			String defaultAud, Set<String> keyTypes) throws IOException {
		this.supportedProfiles.put(client, profiles);
		if (defaultScope != null) {
			this.defaultScope.put(client,  defaultScope);
		}
		if (defaultAud != null) {
			this.defaultAud.put(client, defaultAud);
		}
		this.supportedKeyTypes.put(client, keyTypes);
		persist();
	}
	
	/**
	 * Removes a client or RS from the registry.
	 * 
	 * @param id  the identifier of the device
	 * @throws IOException 
	 */
	public void remove(String id) throws IOException {
		this.supportedProfiles.remove(id);
		this.supportedScopes.remove(id);
		Set<String> auds = this.rs2aud.remove(id);
		for (String aud : auds) {
			Set<String> rss = this.aud2rs.get(aud);
			if (rss != null) {
				rss.remove(id);
				this.aud2rs.put(aud, rss);
			}
		}
		this.supportedKeyTypes.remove(id);
		persist();
	}
	
	
	/**
	 * Checks if the given device supports the given profile.
	 * 
	 * @param id  the device identifier
	 * @param profile  the profile identifier
	 * 
	 * @return  true if the device supports the profile, false otherwise
	 */
	public boolean isProfileSupported(String id, String profile) {
		Set<String> profiles = this.supportedProfiles.get(id);
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
	
	/**
	 *  Checks if the given device supports the given key type.
	 *  
	 * @param id  the device identifier
	 * @param keyType  the key type
	 * @return  true if the device supports the key type, false otherwise
	 */
	public boolean isKeyTypeSupported(String id, String keyType) {
		Set<String> keyTypes = this.supportedKeyTypes.get(id);
		if (keyTypes == null || !keyTypes.contains(keyType)) {
			return false;
		}
		return true;
	}
	
	/**
	 * Returns the default scope for this client, if any. Null otherwise.
	 * 
	 * @param client  the identifier of the client
	 * 
	 * @return  the default scope, or Null if there isn't any
	 */
	public String getDefaultScope(String client) {
		return this.defaultScope.get(client);
	}
	
	/**
	 * Returns the default audience for this client, if nay. Null otherwise.
	 * 
	 * @param client  the identifier of the client
	 * 
	 * @return  the default audience, or Null if there isn't any
	 */
	public String getDefaultAud(String client) {
		return this.defaultAud.get(client);
	}
	
	/**
	 * Get the RSs' that identify with this audience.
	 * 
	 * @param aud  the audience parameter
	 * @return  a set of RS identifiers or Null if there aren't any
	 */
	public Set<String> getRS(String aud) {
		return this.aud2rs.get(aud);
	}
	
	/**
	 * Save the current state in the configfile.
	 * 
	 * The configfile is built like this:
	 * 
	 * [
	 * 	{id : [profiles], ...},
	 *  {id : [keyTypes], ...},
	 *  {id : [scopes], ....},
	 *  {id : [audiences], ...},
	 *  {id : default audience, ....} ,
	 *  {id : default scope, ...}
	 * ]
	 * @throws IOException 
	 * 
	 */
	private void persist() throws IOException {
		JSONArray config = new JSONArray();
		JSONObject profiles = new JSONObject(this.supportedProfiles);
		JSONObject keyTypes = new JSONObject(this.supportedKeyTypes);
		JSONObject scopes = new JSONObject(this.supportedScopes);
		JSONObject audiences = new JSONObject(this.rs2aud);
		JSONObject defaultAud = new JSONObject(this.defaultAud);
		JSONObject defaultScope =  new JSONObject(this.defaultScope);
		config.put(profiles);
		config.put(keyTypes);
		config.put(scopes);
		config.put(audiences);
		config.put(defaultAud);
		config.put(defaultScope);
		
		FileOutputStream fos=new FileOutputStream(this.configfile, false);
		fos.write(config.toString().getBytes());
		fos.close();
	}
	
	private void load() throws IOException {
		FileInputStream fis = new FileInputStream(this.configfile);
		Scanner scanner = new Scanner(fis, "UTF-8" );
		Scanner s = scanner.useDelimiter("\\A");
		String configStr = s.hasNext() ? s.next() : "";
		s.close();
		scanner.close();
		fis.close();
		JSONArray config = null;
		if (!configStr.isEmpty()) {
			config = new JSONArray(configStr);
			JSONObject profiles = config.getJSONObject(Registrar.PROFILES);
			JSONObject keyTypes = config.getJSONObject(Registrar.KEYTYPES);
			JSONObject scopes = config.getJSONObject(Registrar.SCOPES);
			JSONObject audiences = config.getJSONObject(Registrar.AUDS);
			JSONObject defaultAud = config.getJSONObject(Registrar.DEFAUD);
			JSONObject defaultScope =  config.getJSONObject(Registrar.DEFSCOPE);
			this.supportedProfiles = parseMap(profiles);
			this.supportedKeyTypes = parseMap(keyTypes);
			this.supportedScopes = parseMap(scopes);
			this.rs2aud = parseMap(audiences);
			this.aud2rs = new HashMap<String, Set<String>>();
			for (Entry<String,Set<String>> e : this.rs2aud.entrySet()) {
				for (String aud : e.getValue()) {
					Set<String> set = this.aud2rs.get(aud);
					if (set == null) {
						set = new HashSet<>();
					}
					set.add(e.getKey());
					this.aud2rs.put(aud, set);
				}
			}
			this.defaultAud = parseSimpleMap(defaultAud);
			this.defaultScope = parseSimpleMap(defaultScope);
		}
	}
	
	private Map<String, Set<String>> parseMap(JSONObject map) {
		Map<String,Object> foo = map.toMap();
		Map<String, Set<String>> bar = new HashMap<>();
		for (Entry<String, Object> e : foo.entrySet()) {
			if (e.getValue() instanceof List<?>) {
				List<String> list = (List<String>)e.getValue();
				Set<String> set = new HashSet<String>();
				set.addAll(list);
				bar.put(e.getKey().toString(), set);
			}
		}
		return bar;
	}
	
	private Map<String,String> parseSimpleMap(JSONObject map) {
		Map<String, Object> foo = map.toMap();
		Map<String, String> bar = new HashMap<>();
		for (Entry<String, Object> e : foo.entrySet()) {
			if (e.getValue() instanceof String) {
				bar.put(e.getKey().toString(), e.getValue().toString());
			}
		}
		return bar;
	}
}
