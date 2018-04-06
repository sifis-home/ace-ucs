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

    @Override
    public void setParams(String user, String pwd, String dbName, String dbUrl) {
        this.user = user;
        if(this.user == null)
        {
            this.user = DBConnector.DEFAULT_USER;
        }
        this.password = pwd;
        if(this.password == null)
        {
            this.password = DBConnector.DEFAULT_PASSWORD;
        }
        this.dbName = dbName;
        if(this.dbName == null)
        {
            this.dbName = DBConnector.DEFAULT_DB_NAME;
        }
        this.baseDbUrl = dbUrl;
        if(this.baseDbUrl == null)
        {
            this.baseDbUrl = DEFAULT_DB_URL;
        }
    }

    @Override
    public Connection getRootConnection(String rootPwd) throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", PostgreSQLDBAdapter.ROOT_USER);
        connectionProps.put("password", rootPwd);
        return DriverManager.getConnection(this.baseDbUrl + "/" + PostgreSQLDBAdapter.BASE_DB, connectionProps);
    }

    @Override
    public Connection getDBConnection() throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", user);
        connectionProps.put("password", password);
        return DriverManager.getConnection(this.baseDbUrl + "/" + this.dbName, connectionProps);
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

        try (Connection rootConn = getRootConnection(rootPwd);
             Statement stmt = rootConn.createStatement())
        {
            stmt.execute(createUser);
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void createDBAndTables(String rootPwd) throws AceException {
        // First check it DB exists.
        String checkDB = "SELECT datname FROM pg_catalog.pg_database WHERE datname = '" + this.dbName + "';";
        try (Connection rootConn = getRootConnection(rootPwd);
             Statement stmt = rootConn.createStatement();
             ResultSet result = stmt.executeQuery(checkDB))
        {
            if (result.next())
            {
                // Treat this as a "create if not exist", so if it exists, end method without doing anything.
                return;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }

        // Create the database.
        String createDB = "CREATE DATABASE " + this.dbName
                + " WITH OWNER= " + this.user + " ENCODING = 'UTF8' TEMPLATE = template0 " +
                " CONNECTION LIMIT = -1;";
        try (Connection rootConn = getRootConnection(rootPwd);
             Statement stmt = rootConn.createStatement())
        {
            stmt.execute(createDB);
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

        // Table creation in PostgreSQL needs to be done with a connection using the local user and not the root user,
        // so that the local user will be automatically set as the owner of the tables.
        try (Connection rootConn = getDBConnection();
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
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public String updateEngineSpecificSQL(String sqlQuery)
    {
        // In PostgreSQL, enums need casting.
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(
                DBConnector.keyTypesTable)) {
            return "INSERT INTO " + DBConnector.keyTypesTable 
                    + " VALUES (?,?::keytype)";
        }
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(
                DBConnector.tokenTypesTable)) {
            return "INSERT INTO " + DBConnector.tokenTypesTable 
                    + " VALUES (?,?::tokentype)";
        }

        // Create table statements do not take the db name in PostgreSQL.
        if (sqlQuery.contains("CREATE TABLE IF NOT EXISTS ")) {
           String ret = sqlQuery.replace("CREATE TABLE IF NOT EXISTS ", 
                    "CREATE TABLE ");
           if (sqlQuery.contains(this.dbName + ".")) {
               ret = sqlQuery.replace(this.dbName + ".", "");
           }
           return ret;
        }        
        return sqlQuery;
    }

    @Override
    public void wipeDB(String rootPwd) throws AceException
    {
        try (Connection rootConn = getRootConnection(rootPwd);
             Statement stmt = rootConn.createStatement())
        {
            String dropConnections = "SELECT pg_terminate_backend(pg_stat_activity.pid) " +
                    "    FROM pg_stat_activity " +
                    "    WHERE pg_stat_activity.datname = '" + dbName + "'" +
                    "      AND pid <> pg_backend_pid();";
            String dropDB = "DROP DATABASE IF EXISTS " + dbName + ";";
            String dropUser = "DROP USER IF EXISTS " + user + ";";
            stmt.execute(dropConnections);
            stmt.execute(dropDB);
            stmt.execute(dropUser);
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
}
