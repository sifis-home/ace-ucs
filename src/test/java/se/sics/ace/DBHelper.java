package se.sics.ace;

import se.sics.ace.AceException;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.examples.MySQLDBAdapter;
//import se.sics.ace.examples.PostgreSQLDBAdapter;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.SQLException;

/**
 * Helper class to set up databases for tests.
 *
 * @author Sebastian Echeverria and Marco Tiloca and Marco Rasori
 *
 */
public class DBHelper
{
    /**
     * Easy place to change which DB adapter wants to be used for all tests.
     */
    private static SQLDBAdapter dbAdapter = new MySQLDBAdapter(); //PostgreSQLDBAdapter();

    private static String testUsername = "testuser";
    private static String testPassword = "testpwd";
    private static String testDBName = "testdb";

    private static String dbAdminUser = null;
    private static String dbAdminPwd = null;
    private static String dbUrl = null;

    protected static void restoreDefaultClassFields() {
        dbAdapter = new MySQLDBAdapter();

        testUsername = "testuser";
        testPassword = "testpwd";
        testDBName = "testdb";

        dbAdminUser = null;
        dbAdminPwd = null;
        dbUrl = null;
    }

    /**
     * Sets up the DB using the current default adapter.
     *
     * @throws AceException if acting on the database fails
     * @throws IOException if loading admin information fails
     */
    public static void setUpDB(String dbUrl) throws AceException, IOException
    {
        // First load the DB admin username and password from an external file.
        try {
            loadAdminLoginInformation();
        } catch (IOException e) {
            // if the dbUrl is not empty, later we try to load admin username and password from the URL
            if (dbUrl == null) {
                throw new IOException(e.getMessage());
            }
        }

        // Parse the DB url.
        // If the url includes db credentials, these will be used,
        // and they possibly override those loaded from the db.pwd file
        try {
            parseDbUrl(dbUrl);
        } catch (URISyntaxException e) {
            throw new AceException(e.getMessage());
        }

        if (dbAdminUser == null || dbAdminPwd == null) {
            throw new AceException("Cannot retrieve admin username and password for the database");
        }

        // Set parameters for the DB.
        dbAdapter.setParams(testUsername, testPassword, testDBName, DBHelper.dbUrl);

        // In case database and/or user already existed.
        SQLConnector.wipeDatabase(dbAdapter, dbAdminUser, dbAdminPwd);

        // Create the DB and user for the tests.
        SQLConnector.createUser(dbAdapter, dbAdminUser, dbAdminPwd);
        SQLConnector.createDB(dbAdapter, dbAdminUser, dbAdminPwd);
    }

    /**
     * @return  the SQLConnector instance
     * @throws SQLException if an error occurs retrieving the database instance
     */
    public static SQLConnector getSQLConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return SQLConnector.getInstance(dbAdapter);
    }

    /**
     * @return the CoapDBConnector instance
     * @throws SQLException if an error occurs when retrieving the CoapDBConnector istance
     */
    public static CoapDBConnector getCoapDBConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return CoapDBConnector.getInstance(dbAdapter);
    }

    /**
     * Destroy the test DB with the default adapter.
     * @throws AceException if an error occurs when wiping the database
     */
    public static void tearDownDB() throws AceException
    {
        dbAdapter.setParams(testUsername, testPassword, testDBName, null);
        SQLConnector.wipeDatabase(dbAdapter, dbAdminUser, dbAdminPwd);
    }

    /**
     * Loads the admin username and password form an external file.
     * @throws IOException if an error occurs when retrieving the file with the credentials for the database
     */
    private static void loadAdminLoginInformation() throws IOException
    {
        try (BufferedReader br = new BufferedReader(new FileReader("db.pwd"))) {
            int readLines = 0;
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null && readLines < 2) {
                sb.delete(0, sb.length());
                sb.append(line);
                sb.append(System.lineSeparator());

                if (readLines == 0) {
                    dbAdminUser = sb.toString().replace(System.getProperty("line.separator"), "");
                }
                if (readLines == 1) {
                    dbAdminPwd = sb.toString().replace(System.getProperty("line.separator"), "");
                }
                readLines++;
                line = br.readLine();
            }
        }
    }

    /**
     * Parse the database url provided as input.
     * This method returns null if the string passed as argument is null.
     * This method accepts only urls that start with "jdbc:mysql://" and ignores
     * the path of the url, if any.
     * It returns a string in the form "jdbc:mysql://host:port". If the port is not
     * specified in the provided url, it places the default port (3306) in the
     * returned string
     *
     * @param url the url of the database
     * @throws URISyntaxException If the given string violates RFC 2396
     */
    private static void parseDbUrl(String url) throws URISyntaxException, AceException {
        if (url == null) {
            // using default db Url
            return;
        }
        if (!url.startsWith("jdbc:mysql://")) {
            throw new IllegalArgumentException("Wrong database URL. The URL must start with \"jdbc:mysql://\"");
        }
        //strip off the jdbc: part
        url = url.substring(5);

        URI uri = new URI(url);
        String host = uri.getHost();
        int port = uri.getPort();

        if (host == null) {
            throw new AceException("Wrong database URL. The host cannot be parsed");
        }

        // if the port is not defined, use the default port (3306)
        if (port != -1) {
            dbUrl = "jdbc:mysql://" + host + ":" + port;
        }
        else {
            dbUrl = "jdbc:mysql://" + host + ":3306";
        }

        overrideCredentials(uri);
    }

    /**
     * Set admin username and password, if provided.
     * This method possibly overrides the admin credentials provided within the db.pwd file.
     *
     * @param uri the URI
     * @throws AceException if some error occurs during parsing of the URI
     */
    private static void overrideCredentials(URI uri) throws AceException {

        String credentials = uri.getUserInfo();
        if (credentials == null) {
            return;
        }
        String[] splitCredentials = credentials.split(":");
        if (splitCredentials.length > 2) {
            throw new AceException("Wrong database URL. User info cannot be parsed. Too many colons");
        }

        if (splitCredentials[0].equals("")) {
            throw new AceException("Wrong database URL. Username cannot be empty");
        }
        dbAdminUser = splitCredentials[0];

        // if password is present
        if (splitCredentials.length == 2) {
            dbAdminPwd = splitCredentials[1];
        }
        else {
            dbAdminPwd = "";
        }
        if (dbAdminPwd.equals("")) {
            System.out.println("Warning: no password for user " + dbAdminUser + " was specified. " +
                    "Using an empty password..." );
        }

        System.out.println("Credentials loaded from the provided database URI");
    }
}