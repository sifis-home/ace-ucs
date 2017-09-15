/*******************************************************************************
 * AAIoT update to ACE-Java
 *
 * Copyright 2017 Carnegie Mellon University. All Rights Reserved.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 * UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO
 * ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD-style license, please see sei-license.txt or contact
 * permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public
 * release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 * This Software includes and/or makes use of the following Third-Party Software
 * subject to its own license:
 *
 * 1. ACE-Java (https: * bitbucket.org/lseitz/ace-java) Copyright 2016 SICS
 * Swedish ICT AB.
 *
 * DM17-0098
 *******************************************************************************/
package se.sics.ace.examples;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSet;
import java.util.Properties;

/**
 * This class handles proper PostgreSQL Db SQL.
 *
 * @author Sebastian Echeverria
 *
 */
public class PostgreSQLDBAdapter implements SQLDBAdapter {

    /**
     * The default root-user name
     */
    public static final String ROOT_USER = "postgres";
    
    /**
     * The default database name
     */
    public static final String BASE_DB = "postgres";

    /**
     * The default connection URL for the database.
     */
    public static final String DEFAULT_DB_URL = "jdbc:postgresql://localhost:5432";

    protected String user;
    protected String password;
    protected String baseDbUrl;
    protected String dbName;

    protected String internalDbURL;
    protected String actualDbUrl;

    @Override
    public void setParams(String user, String pwd, String dbName, String dbUrl) {
        this.user = user;
        this.password = pwd;
        this.dbName = dbName;
        if(this.dbName == null)
        {
            this.dbName = DBConnector.dbName;
        }
        this.baseDbUrl = dbUrl;
        if(this.baseDbUrl == null)
        {
            this.baseDbUrl = DEFAULT_DB_URL;
        }

        this.internalDbURL = this.baseDbUrl + "/" + PostgreSQLDBAdapter.BASE_DB;
        this.actualDbUrl = this.baseDbUrl + "/" + this.dbName;
    }

    @Override
    public synchronized void createUser(String rootPwd) throws AceException {
        String createUser = "DO\n" +
                "$body$\n" +
                "BEGIN\n" +
                "   IF NOT EXISTS (\n" +
                "      SELECT *\n" +
                "      FROM   pg_catalog.pg_user\n" +
                "      WHERE  usename = '" +  this.user + "') THEN\n" +
                "\n" +
                "      CREATE ROLE " +  this.user + " LOGIN PASSWORD '" +  this.password + "';\n" +
                "   END IF;\n" +
                "END\n" +
                "$body$;";

        Properties connectionProps = new Properties();
        connectionProps.put("user", PostgreSQLDBAdapter.ROOT_USER);
        connectionProps.put("password", rootPwd);
        try (Connection rootConn = DriverManager.getConnection(this.internalDbURL, connectionProps);
             Statement stmt = rootConn.createStatement())
        {
            stmt.execute(createUser);
            rootConn.close();
            stmt.close();
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void createDBAndTables(String rootPwd) throws AceException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", PostgreSQLDBAdapter.ROOT_USER);
        connectionProps.put("password", rootPwd);

        // First check it DB exists.
        String checkDB = "SELECT datname FROM pg_catalog.pg_database WHERE datname = '" + this.dbName + "';";
        try (Connection rootConn = DriverManager.getConnection(this.internalDbURL, connectionProps);
             Statement stmt = rootConn.createStatement())
        {
            ResultSet result = stmt.executeQuery(checkDB);
            if (result.next())
            {
                // For consistency with other DB adapters, do nothing in this case.
                result.close();
                rootConn.close();
                stmt.close();
                return;
            }
            result.close();
            rootConn.close();
            stmt.close();
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }

        // Create the database.
        String createDB = "CREATE DATABASE " + this.dbName
                + " WITH OWNER= " + this.user + " ENCODING = 'UTF8' TEMPLATE = template0 " +
                " CONNECTION LIMIT = -1;";
        try (Connection rootConn = DriverManager.getConnection(this.internalDbURL, connectionProps);
             Statement stmt = rootConn.createStatement())
        {
            stmt.execute(createDB);
            rootConn.close();
            stmt.close();
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }

        //rs id, cose encoding, default expiration time, psk, rpk
        String createRs = "CREATE TABLE " +  DBConnector.rsTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.expColumn + " bigint NOT NULL, "
                + DBConnector.pskColumn + " bytea, "
                + DBConnector.rpkColumn + " bytea,"
                + "PRIMARY KEY (" + DBConnector.rsIdColumn + "));";

        String createC = "CREATE TABLE " +  DBConnector.cTable + " ("
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.defaultAud + " varchar(255), "
                + DBConnector.defaultScope + " varchar(255), "
                + DBConnector.pskColumn + " bytea, "
                + DBConnector.rpkColumn + " bytea,"
                + DBConnector.needClientToken + " boolean, "
                + "PRIMARY KEY (" + DBConnector.clientIdColumn + "));";

        String createProfiles = "CREATE TABLE "
                + DBConnector.profilesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.profileColumn + " varchar(255) NOT NULL);";

        String keyType = "CREATE TYPE keytype AS ENUM ('PSK', 'RPK', 'TST');";

        String createKeyTypes = "CREATE TABLE "
                + DBConnector.keyTypesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.keyTypeColumn + " keytype);";

        String createScopes = "CREATE TABLE "
                + DBConnector.scopesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.scopeColumn + " varchar(255) NOT NULL);";

        String tokenType = "CREATE TYPE tokenType AS ENUM ('CWT', 'REF', 'TST');";

        String createTokenTypes = "CREATE TABLE "
                + DBConnector.tokenTypesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.tokenTypeColumn + " tokenType);";

        String createAudiences = "CREATE TABLE "
                + DBConnector.audiencesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.audColumn + " varchar(255) NOT NULL);";

        String createCose =  "CREATE TABLE "
                + DBConnector.coseTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.coseColumn + " varchar(255) NOT NULL);";

        String createClaims = "CREATE TABLE "
                + DBConnector.claimsTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " bytea);";
        
        String createOldTokens = "CREATE TABLE "
                + DBConnector.oldTokensTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " bytea);";
        
        String createCtiCtr = "CREATE TABLE "
                + DBConnector.ctiCounterTable + "("
                + DBConnector.ctiCounterColumn + " bigint);";

        String initCtiCtr = "INSERT INTO "
                + DBConnector.ctiCounterTable
                + " VALUES (0);";

        String createTokenLog = "CREATE TABLE "
                + DBConnector.cti2clientTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL,"
                + " PRIMARY KEY (" + DBConnector.ctiColumn + "));";

        connectionProps = new Properties();
        connectionProps.put("user", this.user);
        connectionProps.put("password", this.password);
        try (Connection rootConn = DriverManager.getConnection(this.actualDbUrl, connectionProps);
             Statement stmt = rootConn.createStatement())
        {
            stmt.execute(createRs);
            stmt.execute(createC);
            stmt.execute(createProfiles);
            stmt.execute(keyType);
            stmt.execute(createKeyTypes);
            stmt.execute(createScopes);
            stmt.execute(tokenType);
            stmt.execute(createTokenTypes);
            stmt.execute(createAudiences);
            stmt.execute(createCose);
            stmt.execute(createClaims);
            stmt.execute(createOldTokens);
            stmt.execute(createCtiCtr);
            stmt.execute(initCtiCtr);
            stmt.execute(createTokenLog);
            rootConn.close();
            stmt.close();
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public String updateEngineSpecificSQL(String sqlQuery)
    {
        // In PostgreSQL, enums need casting.
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(DBConnector.keyTypesTable)) {
            return "INSERT INTO " + DBConnector.keyTypesTable + " VALUES (?,?::keytype)";
        }
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(DBConnector.tokenTypesTable)) {
            return "INSERT INTO " + DBConnector.tokenTypesTable + " VALUES (?,?::tokentype)";
        }

        return sqlQuery;
    }

    @Override
    public String getDefaultDBURL()
    {
        return PostgreSQLDBAdapter.DEFAULT_DB_URL;
    }


    @Override
    public void wipeDB(String rootPwd) throws AceException
    {
        try
        {
            //Just to be sure if a previous test didn't exit cleanly
            Properties connectionProps = new Properties();
            connectionProps.put("user", ROOT_USER);
            connectionProps.put("password", rootPwd);
            Connection rootConn = DriverManager.getConnection(DEFAULT_DB_URL + "/" + BASE_DB, connectionProps);
            String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
            Statement stmt = rootConn.createStatement();
            stmt.execute(dropDB);
            stmt.close();
            rootConn.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
}
