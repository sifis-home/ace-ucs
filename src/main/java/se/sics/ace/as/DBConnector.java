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
package se.sics.ace.as;

import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;

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
	public String dbName = "AceASdb";
	
	//******************New table********************************	

	/**
     * The table of token claims
     */
    public String claimsTable = "Claims";
    
	/**
	 * The column for token identifiers (Cid)
	 */
	public String cidColumn = "Cid";
		
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

    
	
	/**
	 * Create the necessary database and tables. Requires the
	 * root user password.
	 * 
	 * @param rootPwd  the root user password
	 * 
	 * @throws AceException 
	 */
	public void init(String rootPwd) throws AceException;
	
	/**
	 * Gets a common profile supported by a specific audience and client.
	 * 
	 * @param audience  the audience identifier
	 * @param clientId  the client identifier
	 * @return  a profile they all support or null if there isn't any
	 * 
	 * @throws AceException 
	 */
	public String getSupportedProfile(String audience, String clientId) 
	            throws AceException;
    
	/**
     * Returns a common key type for the proof-of-possession
     * algorithm, or null if there isn't any.
     * 
     * @param clientId  the id of the client
     * @param aud  the audience that this client is addressing 
     * 
     * @return  a key type both support or null
	 * @throws AceException 
     */
    public String getSupportedPopKeyType(String clientId, String aud)
        throws AceException;
    
    /**
     * Returns a common token type, or null if there isn't any
     * 
     * @param aud  the audience that is addressed
     * 
     * @return  a token type the audience supports or null
     * @throws AceException 
     */
    public Integer getSupportedTokenType(String aud) throws AceException;
    
    /**
     * Returns a common set of COSE message parameters used to protect
     * the access token, for an audience, null if there is no common one.
     * 
     * Note: For a asymmetric key message like Sign0, we assume that the 
     * RS has the AS's public key and can handle public key operations.
     * 
     * @param aud  the audience id
     * @return  the COSE parameters or null
     * @throws AceException 
     * @throws CoseException 
     */
    public COSEparams getSupportedCoseParams(String aud) 
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
     * @param client  the client identifier
     * 
     * @return  the default scope used by this client if any
     * 
     * @throws AceException 
     */
    public String getDefaultScope(String client) throws AceException;

    /**
     * Get the default audience of this client
     *  
     * @param client  the client identifier
     * 
     * @return  the default audience used by this client if any
     * 
     * @throws AceException 
     */
    public String getDefaultAudience(String client) throws AceException;  
    
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
     * Returns the smallest expiration time for the RS in this
     *     audience.
     *     
     * @param aud  the audience of the access token
     * @return  the expiration time in milliseconds
     * 
     * @throws AceException 
     */
    public long getExpTime(String aud) throws AceException;
    
    /**
     * Gets the audiences that this RS is part of.
     * Note that the rs identifier is always a singleton audience itself.
     * 
     * @param rs  the rs identifier
     *
     * @return  the audience identifiers that this RS is part of
     * 
     * @throws AceException 
     */
    public Set<String> getAudiences(String rs) 
                throws AceException;  

    /**
     * Get the shared symmetric key (PSK) with this RS
     *  
     * @param rs  the rs identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws AceException 
     */
    public byte[] getRsPSK(String rs)
        throws AceException;
    
    /**
     * Get the public key (RPK) of this RS
     *  
     * @param rs  the rs identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws AceException 
     */
    public CBORObject getRsRPK(String rs)
        throws AceException;
    
    /**
     * Get the shared symmetric key (PSK) with this client
     *  
     * @param client  the client identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws AceException 
     */
    public byte[] getCPSK(String client)
        throws AceException;
    
    /**
     * Get the public key (RPK) of this client
     *  
     * @param client  the client identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws AceException 
     */
    public CBORObject getCRPK(String client)
        throws AceException;
    
	/**
	 * Creates a new RS. Must provide either a sharedKey or a publicKey.
	 * 
     * @param rs  the identifier for the RS
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
	public void addRS(String rs, Set<String> profiles, Set<String> scopes, 
            Set<String> auds, Set<String> keyTypes, Set<Integer> tokenTypes, 
            Set<COSEparams> cose, long expiration, byte[] sharedKey, 
            CBORObject publicKey) throws AceException;
	/**
	 * Deletes an RS and all related registration data.
	 * 
	 * @param rs  the identifier of the RS
	 * 
	 * @throws AceException
	 */
	public void deleteRS(String rs) 
			throws AceException;
	
	/**
	 * Adds a new client to the database.
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
     *       
	 * @throws AceException 
	 */
	public void addClient(String client, Set<String> profiles, 
	        String defaultScope, String defaultAud, Set<String> keyTypes, 
	        byte[] sharedKey, CBORObject publicKey) 
	                throws AceException;
	
	/**
	 * Deletes a client and all related data
	 * 
	 * @param client  the identifier for the client
	 * 
	 * @throws AceException 
	 */
	public void deleteClient(String client) throws AceException;

	
	/**
	 * Adds a new token to the database
	 * @param cti  the token identifier encoded Base64
	 * @param claims  the claims of this token
	 * 
	 * @throws AceException 
	 */
	public void addToken(String cti, Map<String, CBORObject> claims) 
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
     * @param cti  the token identifier
     * 
     * @return  the set of claims
     *  
     * @throws AceException
     */
    public Map<String, CBORObject> getClaims(String cti) throws AceException;
    
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws AceException
	 */
	public void close() throws AceException;

}
