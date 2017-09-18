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

/**
 * Handles creating user, database and tables to store authorization data.
 *
 * @author Sebastian Echeverria
 */
public interface SQLDBAdapter {
    /**
     * Sets basic params for user and DB creation.
     *
     * @param user username for the DB.
     * @param pwd password for the user.
     * @param dbName the DB name.
     * @param dbUrl the URL to connect to this database type. Can be null, and default URL will be used.
     */
    void setParams (String user, String pwd, String dbName, String dbUrl);

    /**
     * Creates a new user in the DB.
     *
     * @param rootPwd the root or base password to use.
     * @throws AceException
     */
    void createUser(String rootPwd) throws AceException;

    /**
     * Creates a new DB and the appropriate tables to handle authorization data.
     *
     * @param rootPwd
     * @throws AceException
     */
    void createDBAndTables(String rootPwd) throws AceException;


    /**
     * Totally deletes a DB.
     *
     * @param rootPwd the root or base password to use.
     * @throws AceException
     */
    void wipeDB(String rootPwd) throws AceException;

    /**
     * Updates any SQL queries that need to be specific for each DB engine.
     * 
     * @param sqlQuery  the query that should be updated
     * 
     * @return  the updated query
     * 
     */
    String updateEngineSpecificSQL(String sqlQuery);

    /**
     * Gets the default DB URL for this adapter.
     * @return The JDBC URL.
     */
    String getDefaultDBURL();
    
    /**
     * Gets the default root user name for this adapter.
     * @return the default root user name
     */
    String getDefaultRoot();
}
