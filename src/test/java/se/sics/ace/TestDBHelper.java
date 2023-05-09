package se.sics.ace;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;


public class TestDBHelper {

    @Before
    public void cleanDBHelper() {
        DBHelper.restoreDefaultClassFields();
    }

    /**
     * Test the DBHelper with default URI.
     *
     */
    @Test
    public void testSucceedDefaultURI() throws AceException, IOException {
        DBHelper.setUpDB(null);
        DBHelper.tearDownDB();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFailBadScheme() throws AceException, IOException {
        DBHelper.setUpDB("http://fail:3000");
    }

    @Test(expected = AceException.class)
    public void testFailCredentialsTooManyColon() throws AceException, IOException {
        DBHelper.setUpDB("jdbc:mysql://user:pwd:foo@fail:3000");
    }

    @Test(expected = AceException.class)
    public void testFailCredentialsNoUsername() throws AceException, IOException {
        DBHelper.setUpDB("jdbc:mysql://:pwd@fail:3000");
    }

    @Test
    public void testWarningCredentialsNoPassword() throws AceException, IOException {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        try {
            DBHelper.setUpDB("jdbc:mysql://user@localhost:3306");
        }
        // exception is thrown afterward, because the user 'user' with no password
        // gets access denied when trying to wipe the database
        catch (AceException e) {
            // this exact output tells us that the password is indeed empty
            assertEquals("Warning: no password for user user was specified. Using an empty password...\n" +
                    "Credentials loaded from the provided database URI\n", outContent.toString());
        }
    }
}
