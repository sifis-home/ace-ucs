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
package se.sics.ace;

import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.examples.MySQLDBAdapter;
//import se.sics.ace.examples.PostgreSQLDBAdapter;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Helper class to set up databases for tests.
 *
 * @author Sebastian Echeverria
 *
 */
public class DBHelper
{
    /**
     * Easy place to change which DB adapter wants to be used for all tests.
     */
    private static final SQLDBAdapter dbAdapter = new MySQLDBAdapter(); //PostgreSQLDBAdapter();

    private static final String testUsername = "testuser";
    private static final String testPassword = "testpwd";
    private static final String testDBName = "testdb";

    private static String dbRootPwd = null;

    /**
     * Sets up the DB using the current default adapter.
     * 
     * @throws AceException 
     * @throws IOException 
     */
    public static void setUpDB() throws AceException, IOException
    {
        // First load the DB root password from an external file.
        loadRootPassword();

        // Set parameters for the DB.
        dbAdapter.setParams(testUsername, testPassword, testDBName, null);

        // In case database and/or user already existed.
        SQLConnector.wipeDatabase(dbAdapter, dbRootPwd);

        // Create the DB and user for the tests.
        SQLConnector.createUser(dbAdapter, dbRootPwd);
        SQLConnector.createDB(dbAdapter, dbRootPwd);
    }

    /**
     * @return  the SQLConnector instance
     * @throws SQLException
     */
    public static SQLConnector getSQLConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return SQLConnector.getInstance(dbAdapter);
    }

    /**
     * @return the CoapDBConnector instance
     * @throws SQLException
     */
    public static CoapDBConnector getCoapDBConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return CoapDBConnector.getInstance(dbAdapter);
    }

    /**
     * Destroy the test DB with the default adapter.
     * @throws AceException
     */
    public static void tearDownDB() throws AceException
    {
        dbAdapter.setParams(testUsername, testPassword, testDBName, null);
        SQLConnector.wipeDatabase(dbAdapter, dbRootPwd);
    }

    /**
     * Loads the root password form an external file.
     * @throws IOException
     */
    private static void loadRootPassword() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        try
        {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null)
            {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            dbRootPwd = sb.toString().replace(System.getProperty("line.separator"), "");
        }
        finally
        {
            br.close();
        }
    }
}
