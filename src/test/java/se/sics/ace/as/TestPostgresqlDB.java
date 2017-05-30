package se.sics.ace.as;

import COSE.CoseException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import se.sics.ace.AceException;
import se.sics.ace.examples.PostgreSQLDBAdapter;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * Test the database connection classes using PostgreSQL.
 *
 * @author Sebastian Echeverria.
 */
public class TestPostgresqlDB extends TestDB {

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

        TestMysqlDB.setUp(new PostgreSQLDBAdapter());
    }

    /**
     * Deletes the test DB after the tests
     *
     * @throws SQLException
     * @throws AceException
     */
    @AfterClass
    public static void tearDown() throws SQLException, AceException {
        if(db != null) {
            db.close();
        }

        Properties connectionProps = new Properties();
        connectionProps.put("user", PostgreSQLDBAdapter.ROOT_USER);
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(
                PostgreSQLDBAdapter.DEFAULT_DB_URL + "/" + PostgreSQLDBAdapter.BASE_DB, connectionProps);

        String dropDB = "DROP DATABASE " + DBConnector.dbName + ";";
        String dropUser = "DROP ROLE " + TestDB.testUsername + ";";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);
        stmt.close();
        rootConn.close();
    }
}
