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
package se.sics.ace.as;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.Recipient;
import se.sics.ace.cwt.CwtCryptoCtx;

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
	private static int EXPIRE = 6;
	private static int PSK = 7;
	private static int RPK = 8;
	
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
	 * Identifies the type access tokens an RS supports
	 */
	private Map<String, Set<Integer>> supportedTokens;
	
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
	 * The expiration time for access tokens for a specific RS
	 */
	private Map<String, Long> expiration;
	
	/**
	 * The secret keys shared with RSs and clients
	 */
	private Map<String, byte[]> secretKeys;
	
	/**
	 * The public keys of registered RSs and Clients
	 */
	private Map<String, CBORObject> publicKeys;

	/**
	 * Constructor. Makes an empty registrar
	 * @param configfile  the configuration file
	 * @throws IOException 
	 */
	public Registrar(String configfile) throws IOException {
		this.configfile = configfile;
		this.supportedProfiles = new HashMap<>();
		this.supportedScopes = new HashMap<>();
		this.supportedTokens = new HashMap<>();
		this.rs2aud = new HashMap<>();
		this.supportedKeyTypes = new HashMap<>();
		this.defaultAud = new HashMap<>();
		this.defaultScope = new HashMap<>();
		this.aud2rs = new HashMap<>();
		this.expiration = new HashMap<>();
		this.secretKeys = new HashMap<>();
		this.publicKeys = new HashMap<>();
		load();
	}

	/**
	 * Registers a new RS at this AS.
	 * Note that not both of sharedKey and publicKey may be null!
	 * 
	 * @param rs  the identifier for the RS
	 * @param profiles  the profiles this RS supports
	 * @param scopes  the scopes this RS supports
	 * @param auds  the audiences this RS identifies with
	 * @param keyTypes   the key types this RS supports
	 * @param tokenTypes  the token types this RS supports.
	 *     See <code>AccessTokenFactory</code>
	 * @param expiration  the expiration time for access tokens for this RS 
	 *     or 0 if the default value is used
	 * @param sharedKey  the secret key shared with this RS or null if there
	 *     is none
	 * @param publicKey  the COSE-encoded public key of this RS or null if
	 *     there is none
	 * @throws IOException 
	 * @throws ASException 
	 */
	public void addRS(String rs, Set<String> profiles, Set<String> scopes, 
			Set<String> auds, Set<String> keyTypes, Set<Integer> tokenTypes, 
			long expiration, byte[] sharedKey, CBORObject publicKey)
			        throws IOException, ASException {
		this.supportedProfiles.put(rs, profiles);
		this.supportedScopes.put(rs, scopes);
		this.supportedKeyTypes.put(rs, keyTypes);
		this.supportedTokens.put(rs, tokenTypes);
		Set<String> extAuds = new HashSet<>();
		extAuds.addAll(auds);
		//Add the RS itself as a separate audience
		extAuds.add(rs);
		this.rs2aud.put(rs, extAuds);
		for (String aud : extAuds) {
			Set<String> rss = this.aud2rs.get(aud);
			if (rss == null) {
				rss = new HashSet<>();
			}
			rss.add(rs);
			this.aud2rs.put(aud, rss);
		}

		if (expiration != 0L) {
		    this.expiration.put(rs, expiration);
		}
		if (sharedKey == null && publicKey == null) {
		    throw new ASException("Cannot register RS without a key");
		}
		if (sharedKey != null) {
		    this.secretKeys.put(rs, sharedKey);
		}
		if (publicKey != null) {
		    this.publicKeys.put(rs, publicKey);
		}
		persist();	
	}

	
	/**
	 * Registers a new client at this AS.
	 * Note that not both sharedKey and publicKey may be null!
	 * 
	 * @param client  the identifier for the client
	 * @param profiles  the profiles this client supports
	 * @param defaultScope  the default scope if any, or null
	 * @param defaultAud  the default audience if any, or null
	 * @param keyTypes  the key types this client supports
	 * @param sharedKey  the secret key shared with this client or null if 
	 *     there is none
     * @param publicKey  the COSE-encoded public key of this client or null if
     *      there is none
	 * @param publicKey 
	 * @throws IOException 
	 * @throws ASException 
	 */
	public void addClient(String client, Set<String> profiles, String defaultScope, 
			String defaultAud, Set<String> keyTypes, byte[] sharedKey, 
			CBORObject publicKey) throws IOException, ASException {
		this.supportedProfiles.put(client, profiles);
		if (defaultScope != null) {
			this.defaultScope.put(client,  defaultScope);
		}
		if (defaultAud != null) {
			this.defaultAud.put(client, defaultAud);
		}
		this.supportedKeyTypes.put(client, keyTypes);
		if (sharedKey == null && publicKey == null) {
            throw new ASException("Cannot register RS without a key");
        }
		if (sharedKey != null) {
		    this.secretKeys.put(client, sharedKey);
		}
		if (publicKey != null) {
		    this.publicKeys.put(client, publicKey);
		}
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
		if (auds != null) {
			for (String aud : auds) {
				Set<String> rss = this.aud2rs.get(aud);
				if (rss != null) {
					rss.remove(id);
					this.aud2rs.put(aud, rss);
				}
			}
		}
		this.supportedKeyTypes.remove(id);
		this.supportedTokens.remove(id);
		this.defaultAud.remove(id);
		this.defaultScope.remove(id);
		this.expiration.remove(id);
		this.secretKeys.remove(id);
		this.publicKeys.remove(id);
		persist();
	}
	
	
	/**
	 * Returns a common profile, or null if there isn't any
     *
	 * @param client  the id of the client
	 * @param aud  the audience that this client is addressing
	 * @param rs  the id of the RS
	 * 
	 * @return  a profile both support or null
	 */
	public String getSupportedProfile(String client, String aud) {
		Set<String> rss = this.aud2rs.get(aud);
		Set<String> clientP = this.supportedProfiles.get(client);
		for (String rs : rss) {
			Set<String> rsP = this.supportedProfiles.get(rs);
			for (String profile : clientP) {
				if (!rsP.contains(profile)) {
				    clientP.remove(profile);
				}
			}
		}
		if (clientP.isEmpty()) {
		    return null;
		}
		return clientP.iterator().next();
	}
	
	/**
	 * Returns a common key type, or null if there isn't any
	 * 
	 * @param client  the id of the client
	 * @param aud  the audience that this client is addressing 
	 * 
	 * @return  a key type both support or null
	 */
	public String getSupportedKeyType(String client, String aud) {
	    Set<String> rss = this.aud2rs.get(aud);
		Set<String> clientK = this.supportedKeyTypes.get(client);
		for (String rs : rss) {
		    Set<String> rsK = this.supportedKeyTypes.get(rs);
		    for (String keyType : clientK) {
		        if (!rsK.contains(keyType)) {
		            clientK.remove(keyType);
		        }
		    }
		}
		if (clientK.isEmpty()) {
		    return null;
		}
		return clientK.iterator().next();
	}
	   
    /**
     * Returns a common token type, or null if there isn't any
     * 
     * @param aud  the audience that is addressed
     * 
     * @return  a token type the audience supports or null
     */
    public Integer getSupportedTokenType(String aud) {
        Set<String> rss = this.aud2rs.get(aud);
        Set<Integer> tokenType = null;
        for (String rs : rss) {
            if (tokenType == null) {
                tokenType = this.supportedTokens.get(rs);                
            } else  {
                for (int type : tokenType) {
                    if (!this.supportedTokens.get(rs).contains(type)) {
                        tokenType.remove(type);
                    }
                }
            }
            
        }
        if (tokenType == null) {
            return null;
        }
        if (tokenType.isEmpty()) {
            return null;
        }
        
        return tokenType.iterator().next();
    }
	
	
	/**
	 * Checks if the given audience supports the given scope.
	 * 
	 * @param aud  the audience that is addressed
	 * @param scope  the scope
	 * 
	 * @return  true if the audience supports the scope, false otherwise
	 */
	public boolean isScopeSupported(String aud, String scope) {
	    Set<String> rss = this.aud2rs.get(aud);
        for (String rs : rss) {
            if (!this.supportedScopes.get(rs).contains(scope)) {
                return false;
            }
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
	 * Returns the smallest expiration time for the RS in this
	 *     audience. 0 if the default is to be used.
	 * @param aud  the audience of the access token
	 * @return  the expiration time in milliseconds
	 */
	public long getExpiration(String aud) {
	    long exp = Long.MAX_VALUE;
	    for (String rs : this.aud2rs.get(aud)) {
	        exp =  exp > this.expiration.get(rs) ? exp : this.expiration.get(rs);
	    }
	   if (exp == Long.MAX_VALUE) {
	       return 0;
	   }
	   return exp;
	}
	
	/**
	 * Returns the right type of CwtContext for use with the given audience
	 * or null if the audience does not have a common type of keys.
	 * Note: This assumes that the RS has the AS's public key and can handle 
	 * public key operations, if itself uses RPK for authentication.
	 * 
	 * @param aud  the audience for which we want to create a CWT
	 * @param asPrivateKey the private key of the AS in case Sign1 is used,
	 *     null otherwise
	 * @param alg  the signature algorithm if Sign1 is used, null otherwise
	 * @return   a common CwtCryptoCtx or null if this is not possible
	 * 
	 */
	public CwtCryptoCtx getCommonCwtCtx(String aud, CBORObject asPrivateKey, 
	        CBORObject alg) {
	    Set<String> rss = this.aud2rs.get(aud);
	    boolean psk = true;
	    boolean rpk = true;
	    boolean useMac0 = true;
	    byte[] key = null;
	    CBORObject commonAlg = null;
	    Map<String, byte[]> audKeys = new HashMap<>();
	    for (String rs : rss) {
	        if (rpk && !this.publicKeys.containsKey(rs)) {
	            //one is enough to ruin it for everyone
	            rpk = false;
	        }
	        if (psk && !this.secretKeys.containsKey(rs)) {
	            psk = false;
	            useMac0 = false;
	        } else if (psk) {
	            //Collect all psk in case we need to use Cose_Mac ...
	            audKeys.put(rs, this.secretKeys.get(rs));
	            //... but check if we still can use Cose_Mac0
	            if (useMac0) {
	                if (key == null) {
	                    key = this.secretKeys.get(rs);
	                } else if (!Arrays.equals(key, this.secretKeys.get(rs))) {
	                    useMac0 = false;
	                }
	            }
	        } 
	        if (!(rpk || psk)) {
	            return null;
	        }
	    }
	    if (rpk == true) {//Prefer rpk before psk
	        return CwtCryptoCtx.sign1Create(asPrivateKey, alg);
	    }
	    if (useMac0) {
	        return CwtCryptoCtx.mac0(key, commonAlg);
	    } 
	    //Make the Mac structure with Recipients
	    List<Recipient> recipients = new ArrayList<>();
	    for (byte[] k : audKeys.values()) {
	        Recipient r = new Recipient();
	        //XXX: this specifies the use of the "Direct" key wrap
	        r.addAttribute(HeaderKeys.Algorithm, 
                    AlgorithmID.Direct.AsCBOR(), Attribute.UnprotectedAttributes);
	        CBORObject ck = CBORObject.NewMap();
            ck.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
            ck.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(k));
            r.SetKey(ck); 
	        recipients.add(r);	                
	    }
	    return CwtCryptoCtx.mac(recipients, commonAlg);
	}
	
	/** 
	 * Returns a public key for a specific device (client or RS) or
	 * null if we do not have any.
	 * 
	 * @param id  the device's identifier.
	 * @return  the public key encoded as CBOR object
	 */
	public CBORObject getPublicKey(String id) {
	    if (this.publicKeys.containsKey(id)) {
	       return this.publicKeys.get(id);	        
	    }
	    return null;
	}
	   
    /** 
     * Returns a secret key shared with a specific device (client or RS) or
     * null if we do not have any.
     * 
     * @param id  the device's identifier.
     * @return  the secret key as raw byte array
     */
    public byte[] getSecretKey(String id) {
        if (this.secretKeys.containsKey(id)) {
           return this.secretKeys.get(id);          
        }
        return null;
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
	 *  {id : expiration time, ...}
	 *  {id : sharedKey (base64 encoded), ...}
	 *  {id : publicKey (base64 encoded), ...}
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
		JSONObject expiration = new JSONObject(this.expiration);
		Map<String, String> encSecretKeys = new HashMap<>();
		for (Entry<String, byte[]> foo : this.secretKeys.entrySet()) {
		    encSecretKeys.put(foo.getKey(),
		            Base64.getEncoder().encodeToString(foo.getValue()));
		}
		JSONObject secretKeys = new JSONObject(encSecretKeys);
		Map<String,String> encPublicKeys = new HashMap<>();
		for (Entry<String, CBORObject> bar : this.publicKeys.entrySet()) {
            encPublicKeys.put(bar.getKey(),
                    Base64.getEncoder().encodeToString(
                            bar.getValue().EncodeToBytes()));
        }
		
		JSONObject publicKeys = new JSONObject(encPublicKeys);
		config.put(profiles);
		config.put(keyTypes);
		config.put(scopes);
		config.put(audiences);
		config.put(defaultAud);
		config.put(defaultScope);
		config.put(expiration);
		config.put(secretKeys);
		config.put(publicKeys);
		
		FileOutputStream fos=new FileOutputStream(this.configfile, false);
		fos.write(config.toString(4).getBytes());
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
			JSONObject expiration =  config.getJSONObject(Registrar.EXPIRE);
			JSONObject psk = config.getJSONObject(Registrar.PSK);
			JSONObject rpk = config.getJSONObject(Registrar.RPK);
			this.supportedProfiles = parseMap(profiles);
			this.supportedKeyTypes = parseMap(keyTypes);
			this.supportedScopes = parseMap(scopes);
			this.rs2aud = parseMap(audiences);
			this.aud2rs = new HashMap<>();
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
			this.expiration = new HashMap<>();
	        for (String key : expiration.keySet()) {
	            this.expiration.put(key, expiration.getLong(key));
	        }
	        this.secretKeys = new HashMap<>();
	        for (String id : psk.keySet()) {
	            byte[] rawKey = Base64.getDecoder().decode(psk.getString(id));
	            this.secretKeys.put(id, rawKey);
	        }
	        this.publicKeys = new HashMap<>();
	        for (String id : rpk.keySet()) {
                byte[] rawKey = Base64.getDecoder().decode(rpk.getString(id));
                this.publicKeys.put(id, CBORObject.DecodeFromBytes(rawKey));
            }
		}
	}
	
	private static Map<String, Set<String>> parseMap(JSONObject map) {
		Map<String,Object> foo = map.toMap();
		Map<String, Set<String>> bar = new HashMap<>();
		for (Entry<String, Object> e : foo.entrySet()) {
			if (e.getValue() instanceof List<?>) {
				List<String> list = (List<String>)e.getValue();
				Set<String> set = new HashSet<>();
				set.addAll(list);
				bar.put(e.getKey().toString(), set);
			}
		}
		return bar;
	}
	
	private static Map<String,String> parseSimpleMap(JSONObject map) {
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
