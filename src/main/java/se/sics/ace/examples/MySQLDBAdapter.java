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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;

/**
 * This class handles proper MySQL Db SQL.
 *
 * @author Sebastian Echeverria
 *
 */
public class MySQLDBAdapter implements SQLDBAdapter {
    private static final String ROOT_USER = "root";

    /**
     * The default connection URL for the database.
     */
    protected static final String DEFAULT_DB_URL = "jdbc:mysql://localhost:3306";

    protected String user;
    protected String password;
    protected String dbUrl;
    protected String dbName;

    @Override
    public void setParams(String user, String pwd, String dbName, String dbUrl) {
        this.user = user;
        this.password = pwd;
        this.dbName = dbName;
        this.dbUrl = dbUrl;
        if(this.dbUrl == null)
        {
            this.dbUrl = DEFAULT_DB_URL;
        }
    }

    @Override
    public synchronized void createUser(String rootPwd) throws AceException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", MySQLDBAdapter.ROOT_USER);
        connectionProps.put("password", rootPwd);
        String cUser = "CREATE USER '" + this.user
                + "'@'localhost' IDENTIFIED BY '" + this.password
                + "';";
        String authzUser = "GRANT DELETE, INSERT, SELECT, UPDATE ON "
                + this.dbName + ".* TO '" + this.user + "'@'localhost';";
        try (Connection rootConn = DriverManager.getConnection(
                this.dbUrl, connectionProps);
             Statement stmt = rootConn.createStatement();) {
            stmt.execute(cUser);
            stmt.execute(authzUser);
            stmt.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void createDBAndTables(String rootPwd) throws AceException {

        String createDB = "CREATE DATABASE IF NOT EXISTS " + this.dbName
                + " CHARACTER SET utf8 COLLATE utf8_bin;";

        //rs id, cose encoding, default expiration time, psk, rpk
        String createRs = "CREATE TABLE IF NOT EXISTS " + this.dbName
                + "." + DBConnector.rsTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.expColumn + " bigint NOT NULL, "
                + DBConnector.pskColumn + " varbinary(64), "
                + DBConnector.rpkColumn + " varbinary(255),"
                + "PRIMARY KEY (" + DBConnector.rsIdColumn + "));";

        String createC = "CREATE TABLE IF NOT EXISTS " + this.dbName
                + "." + DBConnector.cTable + " ("
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.defaultAud + " varchar(255), "
                + DBConnector.defaultScope + " varchar(255), "
                + DBConnector.pskColumn + " varbinary(64), "
                + DBConnector.rpkColumn + " varbinary(255),"
                + "PRIMARY KEY (" + DBConnector.clientIdColumn + "));";

        String createProfiles = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.profilesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.profileColumn + " varchar(255) NOT NULL);";

        String createKeyTypes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.keyTypesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.keyTypeColumn + " enum('PSK', 'RPK', 'TST'));";

        String createScopes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.scopesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.scopeColumn + " varchar(255) NOT NULL);";

        String createTokenTypes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.tokenTypesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.tokenTypeColumn + " enum('CWT', 'REF', 'TST'));";

        String createAudiences = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.audiencesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.audColumn + " varchar(255) NOT NULL);";

        String createCose =  "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.coseTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.coseColumn + " varchar(255) NOT NULL);";

        String createClaims = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.claimsTable + "("
                + DBConnector.cidColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " varchar(8) NOT NULL,"
                + DBConnector.claimValueColumn + " varbinary(255));";

        String createCtiCtr = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.ctiCounterTable + "("
                + DBConnector.ctiCounterColumn + " int unsigned);";

        String initCtiCtr = "INSERT INTO "
                + this.dbName + "."
                + DBConnector.ctiCounterTable
                + " VALUES (0);";

        Properties connectionProps = new Properties();
        connectionProps.put("user", MySQLDBAdapter.ROOT_USER);
        connectionProps.put("password", rootPwd);
        try (Connection rootConn = DriverManager.getConnection(
                dbUrl, connectionProps);
             Statement stmt = rootConn.createStatement()) {
            stmt.execute(createDB);
            stmt.execute(createRs);
            stmt.execute(createC);
            stmt.execute(createProfiles);
            stmt.execute(createKeyTypes);
            stmt.execute(createScopes);
            stmt.execute(createTokenTypes);
            stmt.execute(createAudiences);
            stmt.execute(createCose);
            stmt.execute(createClaims);
            stmt.execute(createCtiCtr);
            stmt.execute(initCtiCtr);
            rootConn.close();
            stmt.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public String updateEngineSpecificSQL(String sqlQuery)
    {
        // Nothing to do here, as the default SQL statements in is compatible with MySQL.
        return sqlQuery;
    }
}