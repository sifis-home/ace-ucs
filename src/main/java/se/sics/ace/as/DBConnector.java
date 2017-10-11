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
package se.sics.ace.as;

import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.OneKey;
import se.sics.ace.COSEparams;
import se.sics.ace.AceException;

/**
 * This interface provides database connectivity methods for the 
 * Attribute Authority.
 * 
 * @author Ludwig Seitz
 *
 */
public interface DBConnector {
	/**
	 * The default database name
	 */
	public String dbName = "aceasdb";
	
	//******************New table********************************	

	/**
     * The table of token claims
     */
    public String claimsTable = "Claims";
    
	/**
	 * The column for token identifiers (Cti)
	 */
	public String ctiColumn = "Cti";
		
	/**
	 * The column for the token claim names
	 */
	public String claimNameColumn = "ClaimName";
	
	/**
	 * The column for the token claim values
	 */
	public String claimValueColumn = "ClaimValue"; 
	
	//******************New table********************************   

    /**
     * The table invalid (expired or revoked) tokens
     */
    public String oldTokensTable = "InvalidTokens";
    
	
	//******************New table********************************	
	/**
	 * The table of simple RS registration data
	 * (i.e. data for which there only is one value)
	 */
	public String rsTable = "RSs";
	   
    /**
     * The column name for RS identifier
     */
    public String rsIdColumn = "RsId";
    
    /**
     * The column name for pre-shared keys
     */
    public String pskColumn = "PSK";
    
    /**
     * The column name for raw public keys
     */
    public String rpkColumn = "RPK";

    /**
     * The column name for expiration defaults
     */
    public String expColumn = "Exp";
      
    //******************New table********************************   
	/**
	 * The table of simple client registration data
	 */
	public String cTable = "Clients";
    
    /**
     * The column name for client identifier
     */
    public String clientIdColumn = "ClientId";	
    
    /**
     * The column name for noting that the client needs a client token
     */
    public String needClientToken = "NeedClientToken";
	
	/**
	 * The column name for the default audience use by the client
	 */
    public String defaultAud = "DefaultAud";
    
    /**
     * The column name for the default scope use by the client
     */
    public String defaultScope = "DefaultScope";
    
    //******************New table********************************   	
	/**
	 * The table of supported profiles
	 */
	public String profilesTable = "Profiles";
	
	/**
	 * The column name for identifiers that may be both Clients or RS
	 */
	public String idColumn = "Id";
	
	/**
	 * The column name for the profile
	 */
	public String profileColumn = "Profile";

	//******************New table********************************   
	/**
	 * The table of supported key types, using the values PSK and RPK.
	 */
	public String keyTypesTable = "KeyTypes";
	
	/**
     * The column name for the key type
     */
    public String keyTypeColumn = "Profile";
	
	//******************New table********************************   
	/**
	 * The table of scopes a RS supports
	 */
	public String scopesTable = "Scopes";
	 
	/**
     * The column name for the scope
     */
    public String scopeColumn = "Scope";
    
	
	
	//******************New table********************************   
	/**
	 * The table of token types a RS supports, using the values CWT and REF
	 */
	public String tokenTypesTable = "TokenTypes";
	
	   /**
     * The column name for the token type
     */
    public String tokenTypeColumn = "TokenType";
    
	
	//******************New table********************************   
	/**
	 * The table of audiences an RS identifies with
	 */
	public String audiencesTable = "Audiences";

    /**
     * The column name for Audiences
     */
    public String audColumn = "Aud";
    
  //******************New table********************************   
    /**
     * The table listing the COSE configurations an RS supports
     * for protecting access tokens
     */
    public String coseTable = "CoseParams";

    /**
     * The column name for COSE parameters
     */
    public String coseColumn = "Cose";

  //******************New table********************************   
    /**
     * The table saving the counter for generating cti's
     */
    public String ctiCounterTable = "ctiCounterTable";
    
    /**
     * The column name for cti counter
     */
    public String ctiCounterColumn = "ctiCounter";
    
    //******************New table********************************   
    /**
     * The table saving the association between cti and client identifier
     *     Note: This table uses ctiColumn and clientIdColumn
     */
    public String cti2clientTable = "TokenLog";
    

	/**
	 * Gets a common profile supported by a specific audience and client.
	 * 
     * @param clientId  the client identifier
	 * @param aud  the audiences
	 * 
	 * @return  a profile they all support or null if there isn't any
	 * 
	 * @throws AceException 
	 */
	public String getSupportedProfile(String clientId, Set<String> aud) 
	            throws AceException;
    
	/**
     * Checks if the client only supports a single profile.
     * This is used to determine whether the client assumes 
     * a default profile.
     * 
     * @param clientId  the client identifier 
     * 
     * @return  true if the client only supports one profile,
     * false otherwise
     * 
     * @throws AceException 
     */
    public boolean hasDefaultProfile(String clientId) throws AceException;
	
	/**
     * Returns a common key type for the proof-of-possession
     * algorithm, or null if there isn't any.
     * 
     * @param clientId  the id of the client
     * @param aud  the audiences that this client is addressing 
     * 
     * @return  a key type both support or null
	 * @throws AceException 
     */
    public String getSupportedPopKeyType(String clientId, Set<String> aud)
        throws AceException;
    
    /**
     * Returns a common token type, or null if there isn't any
     * 
     * @param aud  the audiences that are addressed
     * 
     * @return  a token type the audience supports or null
     * @throws AceException 
     */
    public Short getSupportedTokenType(Set<String> aud) throws AceException;
    
    /**
     * Returns a common set of COSE message parameters used to protect
     * the access token, for an audience, null if there is no common one.
     * 
     * Note: For a asymmetric key message like Sign0, we assume that the 
     * RS has the AS's public key and can handle public key operations.
     * 
     * @param aud  the audiences
     * @return  the COSE parameters or null
     * @throws AceException 
     * @throws CoseException 
     */
    public COSEparams getSupportedCoseParams(Set<String> aud) 
            throws AceException, CoseException;
    

    /**
     * Checks if the given audience supports the given scope.
     * 
     * @param aud  the audience that is addressed
     * @param scope  the scope
     * 
     * @return  true if the audience supports the scope, false otherwise
     * @throws AceException 
     */
    public boolean isScopeSupported(String aud, String scope)
            throws AceException;
    
    
    /**
     * Get the default scope of this client
     *  
     * @param clientId  the client identifier
     * 
     * @return  the default scope used by this client if any
     * 
     * @throws AceException 
     */
    public String getDefaultScope(String clientId) throws AceException;

    /**
     * Get the default audience of this client
     *  
     * @param clientId  the client identifier
     * 
     * @return  the default audience used by this client if any
     * 
     * @throws AceException 
     */
    public String getDefaultAudience(String clientId) throws AceException;  
    
    /**
     * Gets the RSs that are part of this audience.
     * 
     * @param aud  the audience identifier
     *
     * @return  the RS identifiers of those that are part of this audience 
     *  or null if that audience is not defined
     * 
     * @throws AceException 
     */
    public Set<String> getRSS(String aud) throws AceException;

	/**
	 * Gets all RSs.
	 *
	 * @return  all registered RS identifiers
	 *  or null if that audience is not defined
	 *
	 * @throws AceException
	 */
	public Set<String> getRSS() throws AceException;
       
    /**
     * Returns the smallest expiration time for the RS in this
     *     audience.
     *     
     * @param aud  the audiences of the access token
     * @return  the expiration time in milliseconds
     * 
     * @throws AceException 
     */
    public long getExpTime(Set<String> aud) throws AceException;
    
    /**
     * Gets the audiences that this RS is part of.
     * Note that the rs identifier is always a singleton audience itself.
     * 
     * @param rsId  the rs identifier
     *
     * @return  the audience identifiers that this RS is part of
     * 
     * @throws AceException 
     */
    public Set<String> getAudiences(String rsId) 
                throws AceException;  

    /**
     * Get the shared symmetric key (PSK) with this RS
     *  
     * @param rsId  the rs identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getRsPSK(String rsId)
        throws AceException;
    
    /**
     * Get the public key (RPK) of this RS
     *  
     * @param rsId  the rs identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getRsRPK(String rsId)
        throws AceException;
    
    /**
     * Get the shared symmetric key (PSK) with this client
     *  
     * @param clientId  the client identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getCPSK(String clientId)
        throws AceException;
    
    /**
     * Get the public key (RPK) of this client
     *  
     * @param clientId  the client identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws AceException 
     */
    public OneKey getCRPK(String clientId)
        throws AceException;
    
	/**
	 * Creates a new RS. Must provide either a sharedKey or a publicKey.
	 * 
     * @param rsId  the identifier for the RS
     * @param profiles  the profiles this RS supports
     * @param scopes  the scopes this RS supports
     * @param auds  the audiences this RS identifies with
     * @param keyTypes   the key types this RS supports
     * @param tokenTypes  the token types this RS supports.
     *     See <code>AccessTokenFactory</code>
     * @param cose the set of supported parameters of COSE wrappers for
     *   access tokens, empty if this RS does not process CWTs
     * @param expiration  the expiration time for access tokens for this RS 
     *     or 0 if the default value is used
     * @param sharedKey  the secret key shared with this RS or null if there
     *     is none
     * @param publicKey  the COSE-encoded public key of this RS or null if
     *     there is none
     *
	 * @throws AceException 
	 */
	public void addRS(String rsId, Set<String> profiles, Set<String> scopes, 
            Set<String> auds, Set<String> keyTypes, Set<Short> tokenTypes, 
            Set<COSEparams> cose, long expiration, OneKey sharedKey, 
            OneKey publicKey) throws AceException;
	/**
	 * Deletes an RS and all related registration data.
	 * 
	 * @param rsId  the identifier of the RS
	 * 
	 * @throws AceException
	 */
	public void deleteRS(String rsId) 
			throws AceException;
	
	/**
	 * Adds a new client to the database.
	 * 
	 * @param clientId  the identifier for the client
     * @param profiles  the profiles this client supports
     * @param defaultScope  the default scope if any, or null
     * @param defaultAud  the default audience if any, or null
     * @param keyTypes  the key types this client supports
     * @param sharedKey  the secret key shared with this client or null if 
     *     there is none
     * @param publicKey  the COSE-encoded public key of this client or null if
     *      there is none
	 * @param needClientToken this client a client token
     *       
	 * @throws AceException 
	 */
	public void addClient(String clientId, Set<String> profiles, 
	        String defaultScope, String defaultAud, Set<String> keyTypes, 
	        OneKey sharedKey, OneKey publicKey, boolean needClientToken) 
	                throws AceException;
	
	/**
	 * Deletes a client and all related data
	 * 
	 * @param clientId  the identifier for the client
	 * 
	 * @throws AceException 
	 */
	public void deleteClient(String clientId) throws AceException;

	/**
	 * @param client  the identifier of the client 
	 * @return  Does this client need a client token?
	 * 
	 * @throws AceException 
	 */
	public boolean needsClientToken(String client) throws AceException;
	
	/**
	 * Adds a new token to the database
	 * @param cti  the token identifier encoded Base64
	 * @param claims  the claims of this token
	 * 
	 * @throws AceException 
	 */
	public void addToken(String cti, Map<Short, CBORObject> claims) 
	        throws AceException;
	
	/**
     * Deletes an existing token from the database
     * @param cti  the token identifier encoded Base64
     * 
     * @throws AceException 
     */
    public void deleteToken(String cti) throws AceException;
    
    /**
     * Deletes all expired tokens from the database
     * 
     * @param now  the current time
     * 
     * @throws AceException 
     */
    public void purgeExpiredTokens(long now) throws AceException;
	
    
    /**
     * Returns the claims associated with this token.
     * 
     * @param cti  the token identifier encoded Base64
     * 
     * @return  the set of claims
     *  
     * @throws AceException
     */
    public Map<Short, CBORObject> getClaims(String cti) throws AceException;
    
    
    /**
     * Load the current cti counter of the token endpoint from the DB.
     * 
     * @return   the value of the cti counter in the DB
     * 
     * @throws AceException
     */
    public Long getCtiCounter() throws AceException;
    
    /**
     * Save the current cti counter from the token endpoint to the DB.
     * 
     * @param cti  the current value of the cti counter
     * 
     * @throws AceException 
     */
    public void saveCtiCounter(Long cti) throws AceException;
    
    /**
     * Save a mapping from token identifier to client identifier for
     *  a newly issued token.
     * @param cti  the token identifier Base64 encoded
     * @param clientId  the client identifier
     * @throws AceException
     */
    public void addCti2Client(String cti, String clientId) throws AceException;

	/**
	 * Get list of all registered client ids.
	 *
	 * @return  the list of client identifiers
	 * @throws AceException
	 */
	public Set<String> getClients() throws AceException;

    /**
     * Get the client identifier that holds a given token
     * identified by its cti.
     * 
     * @param cti  the cti of the token Base64 encoded
     * @return  the client identifier
     * @throws AceException 
     */
    public String getClient4Cti(String cti) throws AceException;
    
    /**
     * Get the token identifiers (cti) for a given client.
     * 
     * @param clientId  the client identifier
     * @return a set of token identifiers Base64 encoded
     * @throws AceException
     */
    public Set<String> getCtis4Client(String clientId) throws AceException;
    
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws AceException
	 */
	public void close() throws AceException;

}
