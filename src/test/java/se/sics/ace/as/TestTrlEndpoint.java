package se.sics.ace.as;

import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Test the trl endpoint class.
 *
 * @author Marco Rasori
 */
public class TestTrlEndpoint {

    private static SQLConnector db = null;
    private static Trl r = null;

    /**
     * Set up tests.
     *
     * @throws AceException
     * @throws SQLException
     * @throws IOException
     * @throws CoseException
     */
    @BeforeClass
    public static void setUp() throws AceException, SQLException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();
        Map<String, String> peerIdentitiesToNames = new HashMap<>();

        peerIdentitiesToNames.put("Id1", "clientA");
        peerIdentitiesToNames.put("Id2", "clientB");
        peerIdentitiesToNames.put("Id3", "rs1");
        peerIdentitiesToNames.put("Id4", "rs2");

        db.addCti2Peers("cti1", "clientB", new HashSet<String>() {{
            add("rs1");
        }});
        db.addRevokedToken("cti1");
        db.addCti2TokenHash("cti1", "tokenHash1");

        db.addCti2Peers("cti2", "clientA", new HashSet<String>() {{
            add("rs1");
        }});
        db.addRevokedToken("cti2");
        db.addCti2TokenHash("cti2", "tokenHash2");

        r = new Trl(db, peerIdentitiesToNames);
    }

    /**
     * Deletes the test DB after the tests
     *
     * @throws Exception
     */
    @AfterClass
    public static void tearDown() throws Exception {
        //pdp.close();

        DBHelper.tearDownDB();
    }

    /**
     * Test the trl endpoint, test should fail with Unauthorized client:
     * Id5 is not allowed to observe
     *
     * @throws Exception
     */
    @Test
    public void testUnauthorizedClient() throws Exception {
        Message msg = new LocalMessage(-1, "Id5", null, (CBORObject) null);
        Message response = r.processMessage(msg);

        assert (response.getMessageCode() == Message.FAIL_UNAUTHORIZED);

        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);

        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());

    }


    /**
     * Test the trl endpoint, test should succeed and return an empty cbor array:
     * Id4 has no pertaining tokens in the trl
     *
     * @throws Exception
     */
    @Test
    public void testSucceedNoHashes() throws Exception {
        Message msg = new LocalMessage(-1, "Id4", null, (CBORObject) null);
        Message response = r.processMessage(msg);

        assert (response.getMessageCode() == Message.CREATED);

        CBORObject hashes = CBORObject.NewArray();

        Assert.assertArrayEquals(hashes.EncodeToBytes(), response.getRawPayload());

    }

    /**
     * Test the trl endpoint, test should succeed and return a cbor array
     * containing token hashes
     *
     * @throws Exception
     */
    @Test
    public void testSucceed() throws Exception {
        Message msg = new LocalMessage(-1, "Id2", null, (CBORObject) null);
        Message response = r.processMessage(msg);

        assert (response.getMessageCode() == Message.CREATED);

        CBORObject hashes = CBORObject.NewArray();
        String tokenHash = "tokenHash1";
        hashes.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));

        Assert.assertArrayEquals(hashes.EncodeToBytes(), response.getRawPayload());

    }

}
