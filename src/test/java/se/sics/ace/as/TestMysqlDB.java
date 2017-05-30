package se.sics.ace.as;

import COSE.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import se.sics.ace.AceException;
import se.sics.ace.examples.MySQLDBAdapter;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

/**
 *
 */
public class TestMysqlDB extends TestDB {
    /**
     * Set up tests.
     * @throws SQLException
     * @throws AceException
     * @throws IOException
     * @throws CoseException
     */
    @BeforeClass
    public static void setUp()
            throws SQLException, AceException, IOException, CoseException {

        TestMysqlDB.setUp(new MySQLDBAdapter());
    }

    /**
     * Deletes the test DB after the tests
     *
     * @throws SQLException
     * @throws AceException
     */
    @AfterClass
    public static void tearDown() throws SQLException, AceException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", MySQLDBAdapter.ROOT_USER);
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(MySQLDBAdapter.DEFAULT_DB_URL,
                connectionProps);

        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        String dropUser = "DROP USER '" + TestDB.testUsername + "'@'localhost';";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);
        stmt.close();
        rootConn.close();
        db.close();
    }
}
