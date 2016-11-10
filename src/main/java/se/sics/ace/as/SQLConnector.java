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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AccessToken;
import se.sics.ace.COSEparams;

/**
 * This class provides SQL database connectivity for the Attribute Authority.
 * 
 * @author Ludwig Seitz
 *
 */
public class SQLConnector implements DBConnector {

	/**
	 * The default user of the database
	 */
	private String defaultUser = "aceUser";
	
	/**
	 * The default password of the default user. 
	 * CAUTION! Only use this for testing, this is very insecure
	 * (but then if you didn't figure that out yourself, I cannot help you
	 * anyway).
	 */
	private String defaultPassword = "password";
	
	/**
	 * The default connection URL for the database. Here we use a 
	 * MySQL database on port 3306.
	 */
	private String defaultDbUrl = "jdbc:mysql://localhost:3306";
	
	/**
	 * A prepared connection.
	 */
	private Connection conn = null;
	
	/**
	 * A prepared INSERT statement to add a new Resource Server.
	 * 
	 * Parameters: rs id, cose encoding, default expiration time, psk, rpk
	 */
	private PreparedStatement insertRS;
	
	/**
     * A prepared DELETE statement to remove a Resource Server
     * 
     * Parameter: rs id.
     */
    private PreparedStatement deleteRS;
    
    /**
     * A prepared SELECT statement to get a set of RS for an audience
     * 
     * Parameter: audience name
     */
    private PreparedStatement selectRS;
    
	/**
	 * A prepared INSERT statement to add a profile supported
	 * by a client or Resource Server
	 * 
	 * Parameters: id, profile name
	 */
	private PreparedStatement insertProfile;
	
	/**
     * A prepared DELETE statement to remove the profiles supported
     * by a client or Resource Server
     * 
     * Parameter: id
     */
    private PreparedStatement deleteProfiles;
	
    /**
     * A prepared SELECT statement to get all profiles for 
     * an audience and a client
     * 
     * Parameters: audience name, client id
     */
    private PreparedStatement selectProfiles;
    
	/**
	 * A prepared INSERT statement to add the key types supported
     * by a client or Resource Server
     * 
     * Parameters: id, key type
	 */
	private PreparedStatement insertKeyType;
	 
	/**
     * A prepared DELETE statement to remove the key types supported
     * by a client or Resource Server
     * 
     * Parameter: id
     */
    private PreparedStatement deleteKeyTypes;
    
    /**
     * A prepared SELECT statement to get a set of key types
     * 
     * Parameters: audience name, client id
     */
    private PreparedStatement selectKeyTypes;
	
	/**
     * A prepared INSERT statement to add the scopes supported
     * by a Resource Server
     * 
     * Parameters: rs id, scope name
     */
    private PreparedStatement insertScope;
    
    /**
     * A prepared DELETE statement to remove the scopes supported
     * by a Resource Server
     * 
     * Parameter: rs id
     */
    private PreparedStatement deleteScopes;   
    
    /**
     * A prepared SELECT statement to get a set of Scopes for a specific RS
     * 
     * Parameter: rs id
     */
    private PreparedStatement selectScopes;
    
    /**
     * A prepared INSERT statement to add an audience a 
     * Resource Server identifies with
     * 
     * Parameter: rs id, audience name
     */
    private PreparedStatement insertAudience;
	
    /**
     * A prepared DELETE statement to remove the audiences
     * a Resource Server identifies with
     * 
     * Parameter: rs id
     */
    private PreparedStatement deleteAudiences;   
    
    /**
     * A prepared SELECT statement to get a set of audiences for an RS
     * 
     * Parameter: rs id
     */
    private PreparedStatement selectAudiences;
    
    /**
     * A prepared INSERT statement to add a token type a 
     * Resource Server supports
     * 
     * Parameters: rs id, token type
     */
    private PreparedStatement insertTokenType;
    
    /**
     * A prepared DELETE statement to remove the token types a
     * a Resource Server supports
     * 
     * Parameter: rs id
     */
    private PreparedStatement deleteTokenTypes;   

    /**
     * A prepared SELECT statement to get a set of token types for an audience
     * 
     * Parameter: audience name
     */
    private PreparedStatement selectTokenTypes;
    
	/**
	 * A prepared INSERT statement to add a new client
	 * 
	 * Parameters: client id, default audience, default scope, psk, rpk
	 */
	private PreparedStatement insertClient;
	
	/**
	 * A prepared DELETE statement to remove a client
	 * 
	 * Parameter: client id
	 */
	private PreparedStatement deleteClient;
	
	/**
	 * A prepared SELECT statement to get the default audience for a client.
	 * 
	 *  Parameter: client id
	 */
	private PreparedStatement selectDefaultAudience;
	
	/**
     * A prepared SELECT statement to get the default scope for a client.
     * 
     *  Parameter: client id
     */
    private PreparedStatement selectDefaultScope;

	/**
	 * A prepared SELECT statement to get the COSE configurations for
	 * an audience.
	 * 
	 * Parameter: audience name
	 */
	private PreparedStatement selectCOSE;
	
	/**
     * A prepared SELECT statement to get the default expiration time for
     *     a RS
     *     
     * Parameter: audience name
     */
    private PreparedStatement selectExpiration;
	
    /**
     * A prepared SELECT statement to get a the pre-shared keys for
     *     an audience
     *     
     * Parameter: audience name
     */
    private PreparedStatement selectRsPSK;
    
    /**
     * A prepared SELECT statement to get the public keys of an audience.
     * 
     * Parameter: audience name
     */
    private PreparedStatement selectRsRPK;
    
    /**
     * A prepared SELECT statement to get a the pre-shared key for
     *     an client.
     * 
     * Parameter: client id
     */
    private PreparedStatement selectCPSK;
    
    /**
     * A prepared SELECT statement to get the public key of a client.
     * 
     * Parameter: client id
     */
    private PreparedStatement selectCRPK;
    
    /**
     * A prepared INSERT statement to add a token to the Tokens table.
     * 
     * Parameter: token cid, token raw bytes
     */
    private PreparedStatement insertToken;
    
    /**
     * A prepared DELETE statement to remove a token from the Tokens table.
     * 
     * Parameter: token cid
     */
    private PreparedStatement deleteToken;
    
    /**
     * A prepared SELECT statement to select a token from the Tokens table.
     * 
     * Parameter: token cid
     */
    private PreparedStatement selectToken;
    
    /**
     * A prepared SELECT statement to fetch token ids and their
     * expiration time form the claims table.
     */
    private PreparedStatement selectExpirationTime;
    
    /**
     * A prepared INSERT statement to add a claim of a token 
     * to the Claims table.
     * 
     * Parameters: token cid, claim name, claim value
     */
    private PreparedStatement insertClaim;
    
    /**
     * A prepared DELETE statement to remove the claims of a token 
     * from the Claims table.
     * 
     * Parameters: token cid
     */
    private PreparedStatement deleteClaims;
    
    /**
     * A prepared SELECT statement to select the claims of a token from
     * the Claims table.
     * 
     * Parameter: token cid
     */
    private PreparedStatement selectClaims;
    
    
	/**
	 * Create a new database connector either from given values or the 
	 * defaults.
	 * 
	 * @param dbUrl  the database URL, if null the default will be used
	 * @param user   the database user, if null the default will be used
	 * @param pwd    the database user's password, if null the default 
	 * 				 will be used
	 * @throws SQLException 
	 */
	public SQLConnector(String dbUrl, String user, String pwd) 
			throws SQLException {
		if (dbUrl != null) {
			this.defaultDbUrl = dbUrl;
		}
		if (user != null) {
			this.defaultUser = user;
		}
		if (pwd != null) {
			this.defaultPassword = pwd;
		}
		Properties connectionProps = new Properties();		
		connectionProps.put("user", this.defaultUser);
		connectionProps.put("password", this.defaultPassword);
		this.conn = DriverManager.getConnection(this.defaultDbUrl, 
				connectionProps);

		this.insertRS = this.conn.prepareStatement("INSERT INTO "
		        + DBConnector.dbName + "." + DBConnector.rsTable
		        + " VALUES (?,?,?,?,?);");
		
		this.deleteRS = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.rsTable
                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		
		this.selectRS = this.conn.prepareStatement("SELECT "
                + DBConnector.rsIdColumn
                + " FROM " + DBConnector.dbName + "." 
                + DBConnector.audiencesTable
                + " WHERE " + DBConnector.audColumn + "=?);");
		        
		this.insertProfile = this.conn.prepareStatement("INSERT INTO "
		        + DBConnector.dbName + "." + DBConnector.profilesTable
		        + " VALUES (?,?)");
		
		this.deleteProfiles = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.profilesTable
                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		
		this.selectProfiles = this.conn.prepareStatement("SELECT * FROM " 
		        + DBConnector.dbName + "." + DBConnector.profilesTable
                + " WHERE " + DBConnector.idColumn + " IN (SELECT " 
                    + DBConnector.rsIdColumn + " FROM " 
                    + DBConnector.dbName + "." + DBConnector.audiencesTable 
                    + " WHERE " + DBConnector.audColumn
                    + "=?) UNION SELECT * FROM " 
                    + DBConnector.dbName + "." + DBConnector.profilesTable
                    + " WHERE " + DBConnector.idColumn + "=?;"); 
			
		this.insertKeyType = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.keyTypesTable
                + " VALUES (?,?)");
		
		this.deleteKeyTypes = this.conn.prepareStatement("DELETE FROM "
	                + DBConnector.dbName + "." + DBConnector.keyTypesTable
	                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		
		this.selectKeyTypes =  this.conn.prepareStatement("SELECT * FROM " 
                + DBConnector.dbName + "." + DBConnector.keyTypesTable
                + " WHERE " + DBConnector.idColumn + " IN (SELECT " 
                    + DBConnector.rsIdColumn + " FROM " 
                    + DBConnector.dbName + "." + DBConnector.audiencesTable
                    + " WHERE " + DBConnector.audColumn + "=?)"
                    + " UNION SELECT * FROM " + DBConnector.dbName + "." 
                    + DBConnector.keyTypesTable + " WHERE " 
                    + DBConnector.idColumn + "=?;");             
		          
		this.insertScope = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.scopesTable
                + " VALUES (?,?)");
		
		this.deleteScopes = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.scopesTable
                + " WHERE " + DBConnector.rsIdColumn + "=?;");

		this.selectScopes = this.conn.prepareStatement("SELECT * FROM " 
                + DBConnector.dbName + "." + DBConnector.scopesTable
                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
                    + DBConnector.rsIdColumn + " FROM " 
                    + DBConnector.dbName + "." + DBConnector.audiencesTable
                    + " WHERE " + DBConnector.audColumn + "=?);");          
		
		this.insertAudience = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.audiencesTable
                + " VALUES (?,?)");
		
		this.deleteAudiences = this.conn.prepareStatement("DELETE FROM "
	                + DBConnector.dbName + "." + DBConnector.audiencesTable
	                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		
		this.selectAudiences = this.conn.prepareStatement("SELECT " 
		        + DBConnector.audColumn + " FROM "
		        + DBConnector.dbName + "." + DBConnector.audiencesTable
                + " WHERE " + DBConnector.rsIdColumn + "=?);");          
		
		this.insertTokenType = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.tokenTypesTable
                + " VALUES (?,?)");
		
		this.deleteTokenTypes = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.tokenTypesTable
                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		
		this.selectTokenTypes = this.conn.prepareStatement("SELECT * FROM " 
                + DBConnector.dbName + "." + DBConnector.tokenTypesTable
                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
                    + DBConnector.rsIdColumn + " FROM " 
                    + DBConnector.dbName + "." + DBConnector.audiencesTable 
                    + " WHERE " + DBConnector.audColumn + "=?);");      
		
		this.insertClient = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.cTable
                + " VALUES (?,?,?,?,?)");
	
		this.deleteClient = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.cTable
                + " WHERE " + DBConnector.cIdColumn + "=?;");
		
		this.selectDefaultAudience = this.conn.prepareStatement("SELECT " 
		        + DBConnector.defaultAud + " FROM " 
                + DBConnector.dbName + "." + DBConnector.cTable
                + " WHERE " + DBConnector.cIdColumn + "=?;");
		  
		this.selectDefaultAudience = this.conn.prepareStatement("SELECT " 
	                + DBConnector.defaultScope + " FROM " 
	                + DBConnector.dbName + "." + DBConnector.cTable
	                + " WHERE " + DBConnector.cIdColumn + "=?;");
		
		this.selectCOSE = this.conn.prepareStatement("SELECT "
		        + DBConnector.coseColumn 
                + " FROM " + DBConnector.dbName + "." + DBConnector.rsTable
                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
                    + DBConnector.rsIdColumn + " FROM " 
                    + DBConnector.dbName + "." + DBConnector.audiencesTable 
                    + " WHERE " + DBConnector.audColumn + "=?);");
	      
		this.selectExpiration = this.conn.prepareStatement("SELECT "
	                + DBConnector.expColumn 
	                + " FROM " + DBConnector.dbName + "." + DBConnector.rsTable
	                + " WHERE " + DBConnector.rsIdColumn + "=?;");
		        
		this.selectRsPSK = this.conn.prepareStatement("SELECT "
		        + DBConnector.pskColumn
		        + " FROM " + DBConnector.dbName + "." + DBConnector.rsTable
		        + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
		            + DBConnector.rsIdColumn + " FROM " 
		            + DBConnector.dbName + "." + DBConnector.audiencesTable
		            + " WHERE " + DBConnector.audColumn + "=?);");

		this.selectRsRPK = this.conn.prepareStatement("SELECT " 
		        + DBConnector.rpkColumn
		        + " FROM " + DBConnector.dbName + "." + DBConnector.rsTable
		        + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
		            + DBConnector.rsIdColumn + " FROM " 
		            + DBConnector.dbName + "." + DBConnector.audiencesTable 
		            + " WHERE " + DBConnector.audColumn + "=?);");

		this.selectCPSK = this.conn.prepareStatement("SELECT "
		        + DBConnector.pskColumn
		        + " FROM " + DBConnector.dbName + "." + DBConnector.cTable
		        + " WHERE " + DBConnector.cIdColumn + "=?;");

		this.selectCRPK = this.conn.prepareStatement("SELECT " 
		        + DBConnector.rpkColumn
		        + " FROM " + DBConnector.dbName + "." + DBConnector.cTable
		        + " WHERE "  + DBConnector.cIdColumn + "=?;");
		
		this.insertToken = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.tokenTable
                + " VALUES (?,?)");
		
		this.deleteToken = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.tokenTable
                + " WHERE " + DBConnector.cidColumn + "=?;");
    
		this.selectToken = this.conn.prepareStatement("SELECT "
		        + DBConnector.tokenColumn + " FROM " 
		        + DBConnector.dbName + "." + DBConnector.tokenTable
		        + " WHERE " + DBConnector.cidColumn + "=?);");  
		
		this.selectExpirationTime = this.conn.prepareStatement("SELECT "
		        + DBConnector.cidColumn + "," + DBConnector.claimValueColumn
		        + " FROM "  + DBConnector.dbName + "." 
		        + DBConnector.claimsTable
		        + " WHERE " + DBConnector.claimNameColumn + "='exp';");
		        
		this.insertClaim = this.conn.prepareStatement("INSERT INTO "
                + DBConnector.dbName + "." + DBConnector.claimsTable
                + " VALUES (?,?,?)");
        
        this.deleteClaims = this.conn.prepareStatement("DELETE FROM "
                + DBConnector.dbName + "." + DBConnector.claimsTable
                + " WHERE " + DBConnector.cidColumn + "=?;");
    
        this.selectClaims = this.conn.prepareStatement("SELECT "
                + DBConnector.claimNameColumn + ","
                + DBConnector.claimValueColumn + " FROM " 
                + DBConnector.dbName + "." + DBConnector.claimsTable
                + " WHERE " + DBConnector.cidColumn + "=?);");  	
	}
	
	/**
	 * Get the prepared Statement object.
	 * 
	 * @return  the prepared Statement
	 * @throws SQLException
	 */
	private Statement getStatement() throws SQLException {
		return this.conn.createStatement();
	}
	
	/**
	 * Create the necessary database and tables. Requires the
	 * root user password.
	 * 
	 * @param rootPwd  the root user password
	 * @throws SQLException 
	 */
	@Override
	public void init(String rootPwd) throws SQLException {
		Properties connectionProps = new Properties();
		connectionProps.put("user", "root");
		connectionProps.put("password", rootPwd);
		Connection rootConn = DriverManager.getConnection(
				this.defaultDbUrl, connectionProps);
		
		String createDB = "CREATE DATABASE IF NOT EXISTS " + DBConnector.dbName
		        + " CHARACTER SET utf8 COLLATE utf8_bin;";

		//rs id, cose encoding, default expiration time, psk, rpk
		String createRs = "CREATE TABLE IF NOT EXISTS " + DBConnector.dbName 
		        + "." + DBConnector.rsTable + "(" 
		        + DBConnector.rsIdColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.coseColumn + " varchar(255) NOT NULL, "
                + DBConnector.expColumn + " bigint NOT NULL, "
		        + DBConnector.pskColumn + " varbinary(32), "
		        + DBConnector.rpkColumn + " varbinary(255));";

		String createC = "CREATE TABLE IF NOT EXISTS " + DBConnector.dbName
		        + "." + DBConnector.cTable + " ("
		        + DBConnector.cidColumn + " varchar(255) NOT NULL, "
		        + DBConnector.defaultAud + " varchar(255), "
		        + DBConnector.defaultScope + " varchar(255), "
                + DBConnector.pskColumn + " varbinary(32), " 
                + DBConnector.rpkColumn + " varbinary(255));";

		String createProfiles = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.profilesTable + "(" 
		        + DBConnector.idColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.profileColumn + " varchar(255) NOT NULL);";
		
		String createKeyTypes = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.keyTypesTable + "(" 
		        + DBConnector.idColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.keyTypeColumn + " enum('PSK', 'RPK'));";

		String createScopes = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.scopesTable + "(" 
		        + DBConnector.rsIdColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.scopeColumn + " varchar(255) NOT NULL);";
	      
		String createTokenTypes = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.tokenTypesTable + "(" 
		        + DBConnector.rsIdColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.tokenTypeColumn + " enum('CWT', 'REF'));";

		String createAudiences = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.audiencesTable + "(" 
		        + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
		        + DBConnector.audColumn + " varchar(255) NOT NULL);";

		String createTokens = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.tokenTable + "(" 
		        + DBConnector.cidColumn + " varchar(255) NOT NULL, "
		        + DBConnector.tokenColumn + " varbinary(500));"; 
		
		String createClaims = "CREATE TABLE IF NOT EXISTS " 
		        + DBConnector.dbName + "."
		        + DBConnector.claimsTable + "(" 
		        + DBConnector.cidColumn + " varchar(255) NOT NULL, " 
		        + DBConnector.claimNameColumn + " varchar(8) NOT NULL," 
		        + DBConnector.claimValueColumn + " varbinary(255));";
	      
		Statement stmt = rootConn.createStatement();
		stmt.execute(createDB);
		stmt.execute(createRs);
		stmt.execute(createC);
		stmt.execute(createProfiles);
		stmt.execute(createKeyTypes);
		stmt.execute(createScopes);
		stmt.execute(createTokenTypes);
		stmt.execute(createAudiences);
		stmt.execute(createTokens);
		stmt.execute(createClaims);
		stmt.close();
		rootConn.close();		
	}
	
	@Override
	@Deprecated
	public synchronized ResultSet executeQuery(String query) 
			throws SQLException {
		Statement stmt = getStatement();
		ResultSet res = stmt.executeQuery(query);
		stmt.close();
		return res;
	}
	
	@Override
	@Deprecated
	public synchronized void executeCommand(String statement) 
			throws SQLException {
		Statement stmt = getStatement();
		stmt.execute(statement);
		stmt.close();
	}
	
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws SQLException
	 */
	@Override
	public void close() throws SQLException {
		this.conn.close();
	}
	
    @Override
    public synchronized ResultSet getProfiles(String audience, String clientId)
            throws SQLException {
        this.selectProfiles.setString(1, audience);
        this.selectProfiles.setString(2, clientId);
        ResultSet result = this.selectProfiles.executeQuery();
        this.selectProfiles.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getkeyTypes(String audience, String clientId)
            throws SQLException {
        this.selectKeyTypes.setString(1, audience);
        this.selectKeyTypes.setString(2, clientId);
        ResultSet result = this.selectKeyTypes.executeQuery();
        this.selectKeyTypes.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getScopes(String audience) throws SQLException {
        this.selectScopes.setString(1, audience);
        ResultSet result = this.selectScopes.executeQuery();
        this.selectScopes.clearParameters();
        return result;
    }

    @Override
    public ResultSet getTokenType(String audience) throws SQLException {
        this.selectTokenTypes.setString(1, audience);
        ResultSet result = this.selectTokenTypes.executeQuery();
        this.selectTokenTypes.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getCose(String audience) throws SQLException {
        this.selectCOSE.setString(1, audience);
        ResultSet result = this.selectCOSE.executeQuery();
        this.selectCOSE.clearParameters();
        return result;
        
    }

    @Override
    public synchronized ResultSet getRSS(String audience) throws SQLException {
        this.selectRS.setString(1, audience);
        ResultSet result = this.selectRS.executeQuery();
        this.selectRS.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getAudiences(String rs) throws SQLException {
        this.selectAudiences.setString(1, rs);
        ResultSet result = this.selectAudiences.executeQuery();
        this.selectAudiences.clearParameters();
        return result;
    }

    @Override
    public synchronized void addRS(String rs, Set<String> profiles, Set<String> scopes,
            Set<String> auds, Set<String> keyTypes, Set<Integer> tokenTypes,
            COSEparams cose, long expiration, byte[] sharedKey,
            CBORObject publicKey) throws SQLException {
        this.insertRS.setString(1, rs);
        this.insertRS.setString(2, cose.toString());
        this.insertRS.setLong(3, expiration);
        this.insertRS.setBytes(4, sharedKey);
        if (publicKey != null) {
            this.insertRS.setBytes(5, publicKey.EncodeToBytes());
        } else {
            this.insertRS.setBytes(5, null);
        }
        this.insertRS.execute();
        this.insertRS.clearParameters();
        
        for (String profile : profiles) {
            this.insertProfile.setString(1, rs);
            this.insertProfile.setString(2, profile);
            this.insertProfile.execute();
        }
        this.insertProfile.clearParameters();
        
        for (String scope : scopes) {
            this.insertScope.setString(1, rs);
            this.insertScope.setString(2, scope);
            this.insertScope.execute();
        }
        this.insertScope.clearParameters();
        
        for (String aud : auds) {
            this.insertAudience.setString(1, rs);
            this.insertAudience.setString(2, aud);
            this.insertAudience.execute();
        }
        this.insertAudience.clearParameters();
        
        for (String keyType : keyTypes) {
            this.insertKeyType.setString(1, rs);
            this.insertKeyType.setString(2, keyType);
            this.insertKeyType.execute();
        }
        this.insertKeyType.clearParameters();
        
        for (int tokenType : tokenTypes) {
            this.insertTokenType.setString(1, rs);
            this.insertTokenType.setString(2, 
                    AccessTokenFactory.ABBREV[tokenType]);
            this.insertTokenType.execute();
        }
        this.insertTokenType.clearParameters();
    }

    @Override
    public synchronized void deleteRS(String rs) throws SQLException {
        this.deleteRS.setString(1, rs);
        this.deleteRS.execute();
        this.deleteRS.clearParameters();
        
        this.deleteProfiles.setString(1, rs);
        this.deleteProfiles.execute();
        this.deleteProfiles.clearParameters();
        
        this.deleteScopes.setString(1, rs);
        this.deleteScopes.execute();
        this.deleteScopes.clearParameters();

        this.deleteAudiences.setString(1, rs);
        this.deleteAudiences.execute();
        this.deleteAudiences.clearParameters();

        this.deleteKeyTypes.setString(1, rs);
        this.deleteKeyTypes.execute();
        this.deleteKeyTypes.clearParameters();
        
        this.deleteTokenTypes.setString(1, rs);
        this.deleteTokenTypes.execute();
        this.deleteTokenTypes.clearParameters();        
    }

    @Override
    public synchronized void addClient(String client, Set<String> profiles,
            String defaultScope, String defaultAud, Set<String> keyTypes,
            byte[] sharedKey, CBORObject publicKey) throws SQLException {
        this.insertClient.setString(1, client);
        this.insertClient.setString(2, defaultAud);
        this.insertClient.setString(3, defaultScope);
        this.insertClient.setBytes(4, sharedKey);
        if (publicKey != null) {
            this.insertClient.setBytes(5, publicKey.EncodeToBytes());
        } else {
            this.insertClient.setBytes(5, null);
        }
        this.insertClient.execute();
        this.insertClient.clearParameters();
        
        for (String profile : profiles) {
            this.insertProfile.setString(1, client);
            this.insertProfile.setString(2, profile);
            this.insertProfile.execute();
        }
        this.insertProfile.clearParameters();
            
        for (String keyType : keyTypes) {
            this.insertKeyType.setString(1, client);
            this.insertKeyType.setString(2, keyType);
            this.insertKeyType.execute();
        }
        this.insertKeyType.clearParameters();       
    }

    @Override
    public synchronized void deleteClient(String client) throws SQLException {
        this.deleteClient.setString(1, client);
        this.deleteClient.execute();
        this.deleteClient.clearParameters();
        
        this.deleteProfiles.setString(1, client);
        this.deleteProfiles.execute();
        this.deleteProfiles.clearParameters();

        this.deleteKeyTypes.setString(1, client);
        this.deleteKeyTypes.execute();
        this.deleteKeyTypes.clearParameters(); 
    }

    @Override
    public synchronized ResultSet getExpTime(String rs) throws SQLException {
        this.selectExpiration.setString(1, rs);
        ResultSet result = this.selectExpiration.executeQuery();
        this.selectExpiration.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getRsPSK(String rs) throws SQLException {
        this.selectRsPSK.setString(1, rs);
        ResultSet result = this.selectRsPSK.executeQuery();
        this.selectRsPSK.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getRsRPK(String rs) throws SQLException {
        this.selectRsRPK.setString(1, rs);
        ResultSet result = this.selectRsRPK.executeQuery();
        this.selectRsRPK.clearParameters();
        return result;
    }
    
    @Override
    public synchronized ResultSet getCPSK(String client) throws SQLException {
        this.selectCPSK.setString(1, client);
        ResultSet result = this.selectCPSK.executeQuery();
        this.selectCPSK.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getCRPK(String client) throws SQLException {
        this.selectCRPK.setString(1, client);
        ResultSet result = this.selectCRPK.executeQuery();
        this.selectCRPK.clearParameters();
        return result;
    }
    
    @Override
    public synchronized ResultSet getDefaultScope(String client) throws SQLException {
        this.selectDefaultScope.setString(1, client);
        ResultSet result = this.selectDefaultScope.executeQuery();
        this.selectDefaultScope.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getDefaultAudience(String client) throws SQLException {
        this.selectDefaultAudience.setString(1, client);
        ResultSet result = this.selectDefaultAudience.executeQuery();
        this.selectDefaultAudience.clearParameters();
        return result;
    }

    @Override
    public synchronized void addToken(String cid, AccessToken token,
            Map<String, CBORObject> claims) throws SQLException {
        this.insertToken.setString(1, cid);
        this.insertToken.setBytes(2, token.encode().EncodeToBytes());
        this.insertToken.execute();
        this.insertToken.clearParameters();
        
        for (Entry<String, CBORObject> claim : claims.entrySet()) {
            this.insertClaim.setString(1, cid);
            this.insertClaim.setString(2, claim.getKey());
            this.insertClaim.setBytes(3, claim.getValue().EncodeToBytes());
            this.insertClaim.execute();
        }
        this.insertClaim.clearParameters();
    }

    @Override
    public synchronized void deleteToken(String cid) throws SQLException {
        this.deleteToken.setString(1, cid);
        this.deleteToken.execute();
        this.deleteToken.clearParameters();
        
        this.deleteClaims.setString(1, cid);
        this.deleteClaims.execute();
        this.deleteClaims.clearParameters();        
    }

    @Override
    public synchronized void purgeExpiredTokens(long now) throws SQLException {
        ResultSet result = this.selectExpirationTime.executeQuery();
        while (result.next()) {
            byte[] rawTime = result.getBytes(DBConnector.claimValueColumn);
            CBORObject cborTime = CBORObject.DecodeFromBytes(rawTime);
            long time = cborTime.AsInt64();
            if (now > time) {
                deleteToken(result.getString(DBConnector.cidColumn));
            }
        }
        result.close();
    }

    @Override
    public synchronized ResultSet getClaims(String cid) throws SQLException {
        this.selectClaims.setString(1, cid);
        ResultSet result = this.selectClaims.executeQuery();
        this.selectClaims.clearParameters();
        return result;
    }

    @Override
    public synchronized ResultSet getToken(String cid) throws SQLException {
       this.selectToken.setString(1, cid);
       ResultSet result = this.selectToken.executeQuery();
       this.selectToken.clearParameters();
       return result;
    }	 
}