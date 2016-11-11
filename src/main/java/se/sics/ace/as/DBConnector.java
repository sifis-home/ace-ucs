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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AccessToken;
import se.sics.ace.COSEparams;

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
	 * The table of tokens (as binary blobs)
	 */	
	public String tokenTable = "Tokens";
	
	/**
	 * The column for token identifiers (Cid)
	 */
	public String cidColumn = "Cid";
	
	/**
	 * The column for the raw token data
	 */
	public String tokenColumn = "Token";
	
	//******************New table********************************	
	/**
	 * The table of token claims
	 */
	public String claimsTable = "Claims";
	
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
	 * @throws SQLException 
	 */
	public void init(String rootPwd) throws SQLException;
	
	/**
	 * Execute a arbitrary query.
	 * CAUTION! This can be a big security risk, use only for
	 * debugging.
	 * 
	 * @param query  the SQL query
	 * @return  the ResultSet of the submitted query
	 * 
	 * @throws SQLException
	 */
	@Deprecated
	public ResultSet executeQuery(String query) throws SQLException;	
	
	/**
	 * Execute a arbitrary database command
	 * CAUTION! This is a big security risk, use only for debugging.
	 * 
	 * @param statement  the database command
	 * 
	 * @throws SQLException
	 */
	@Deprecated
	public void executeCommand(String statement) throws SQLException;
	
	/**
	 * Gets the profiles supported by a specific audience and client
	 * 
	 * @param audience  the audience identifier
	 * @param clientId  the client identifier
	 * @return  the profiles they all support
	 * 
	 * @throws SQLException 
	 */
	public ResultSet getProfiles(String audience, String clientId) 
	            throws SQLException;
    
	/**
     * Gets the key types supported by a specific audience and client
     * 
     * @param audience  the audience identifier
     * @param clientId  the client identifier
     * @return  the key types they all support
     * 
     * @throws SQLException 
     */
    public ResultSet getkeyTypes(String audience, String clientId) 
                throws SQLException;
	
    /**
     * Gets the scopes supported by a specific audience
     * 
     * @param audience  the audience identifier
     *
     * @return  the scopes they all support
     * 
     * @throws SQLException 
     */
    public ResultSet getScopes(String audience) 
                throws SQLException;
    
    /**
     * Gets the token types (CWT or Reference) supported by a specific audience
     * 
     * @param audience  the audience identifier
     *
     * @return  the token types they all support
     * 
     * @throws SQLException 
     */
    public ResultSet getTokenType(String audience) 
                throws SQLException;
    
    /**
     * Gets the Cose encoding for CWTs all members of an audience support
     * 
     * @param audience  the audience identifier
     *
     * @return  the Cose encoding they all support
     * 
     * @throws SQLException 
     */
    public ResultSet getCose(String audience) 
                throws SQLException; 
    
    /**
     * Gets the RSs that are part of this audience.
     * 
     * @param audience  the audience identifier
     *
     * @return  the RS identifiers of those that are part of this audience
     * 
     * @throws SQLException 
     */
    public ResultSet getRSS(String audience) 
                throws SQLException; 
    
    
    /**
     * Gets the audiences that this RS is part of.
     * 
     * @param rs  the rs identifier
     *
     * @return  the audience identifiers that this RS is part of
     * 
     * @throws SQLException 
     */
    public ResultSet getAudiences(String rs) 
                throws SQLException; 
    
    /**
     * Get the default expiration time of access tokens for an RS.
     *  
     * @param rs  the rs identifier
     * 
     * @return  the expiration time
     * 
     * @throws SQLException 
     */
    public ResultSet getExpTime(String rs)
        throws SQLException;
    
    /**
     * Get the shared symmetric key (PSK) with this RS
     *  
     * @param rs  the rs identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws SQLException 
     */
    public ResultSet getRsPSK(String rs)
        throws SQLException;
    
    /**
     * Get the public key (RPK) of this RS
     *  
     * @param rs  the rs identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws SQLException 
     */
    public ResultSet getRsRPK(String rs)
        throws SQLException;
    
    /**
     * Get the shared symmetric key (PSK) with this client
     *  
     * @param client  the client identifier
     * 
     * @return  the shared symmetric key if there is any
     * 
     * @throws SQLException 
     */
    public ResultSet getCPSK(String client)
        throws SQLException;
    
    /**
     * Get the public key (RPK) of this client
     *  
     * @param client  the client identifier
     * 
     * @return  the public key if there is any
     * 
     * @throws SQLException 
     */
    public ResultSet getCRPK(String client)
        throws SQLException;
    
    /**
     * Get the default scope of this client
     *  
     * @param client  the client identifier
     * 
     * @return  the default scope used by this client if any
     * 
     * @throws SQLException 
     */
    public ResultSet getDefaultScope(String client)
        throws SQLException;
    
    /**
     * Get the default audience of this client
     *  
     * @param client  the client identifier
     * 
     * @return  the default audience used by this client if any
     * 
     * @throws SQLException 
     */
    public ResultSet getDefaultAudience(String client)
        throws SQLException;
    
	/**
	 * Creates a new RS.
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
	 * @throws SQLException
	 */
	public void addRS(String rs, Set<String> profiles, Set<String> scopes, 
            Set<String> auds, Set<String> keyTypes, Set<Integer> tokenTypes, 
            Set<COSEparams> cose, long expiration, byte[] sharedKey, CBORObject publicKey) 
			throws SQLException;
	/**
	 * Deletes an RS and all related registration data.
	 * 
	 * @param rs  the identifier of the RS
	 * 
	 * @throws SQLException
	 */
	public void deleteRS(String rs) 
			throws SQLException;
	
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
	 * @throws SQLException 
	 */
	public void addClient(String client, Set<String> profiles, String defaultScope, 
            String defaultAud, Set<String> keyTypes, byte[] sharedKey, 
            CBORObject publicKey) throws SQLException;
	
	/**
	 * Deletes a client and all related data
	 * 
	 * @param client  the identifier for the client
	 * 
	 * @throws SQLException 
	 */
	public void deleteClient(String client) throws SQLException;

	
	/**
	 * Adds a new token to the database
	 * @param cid  the token identifier
	 * @param token  the token raw content
	 * @param claims  the claims of this token
	 * 
	 * @throws SQLException 
	 */
	public void addToken(String cid, AccessToken token, 
	        Map<String, CBORObject> claims) throws SQLException;
	
	/**
     * Deletes an existing token from the database
     * @param cid  the token identifier
     * 
     * @throws SQLException 
     */
    public void deleteToken(String cid) throws SQLException;
    
    /**
     * Selects an existing token from the database
     * @param cid  the token identifier
     * 
     * @return  the raw token data
     * 
     * @throws SQLException
     */
    public ResultSet getToken(String cid) throws SQLException;
    
    
    /**
     * Deletes all expired tokens from the database
     * 
     * @param now  the current time
     * 
     * @throws SQLException 
     */
    public void purgeExpiredTokens(long now) throws SQLException;
	
    
    /**
     * Returns the claims associated with this token.
     * 
     * @param cid  the token identifier
     * 
     * @return  the set of claims
     *  
     * @throws SQLException
     */
    public ResultSet getClaims(String cid) throws SQLException;
    
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws SQLException
	 */
	public void close() throws SQLException;

}
