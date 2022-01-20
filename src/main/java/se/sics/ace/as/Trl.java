package se.sics.ace.as;

import com.upokecenter.cbor.CBORObject;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marco Rasori
 *
 */
public class Trl implements Endpoint, AutoCloseable {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(Trl.class.getName() );

    /**
     * The database connector for storing and retrieving stuff.
     */
    private DBConnector db;

    /**
     * Map between security identities of the peers and their names, used with OSCORE profile;
     * it is null when DTLS profile is used.
     */
    private Map<String, String> peerIdentitiesToNames = null;


    /**
     * Constructor.
     *
     * @param db  the database connector
     * @param peerIdentitiesToNames  mapping between security identities
     *                               of the peers and their names; it can be null
     *
     * @throws AceException  if the db connector is null
     */
    public Trl(DBConnector db, Map<String, String> peerIdentitiesToNames) throws AceException {

        if (db == null) {
            LOGGER.severe("Trl endpoint's DBConnector was null");
            throw new AceException(
                    "Trl endpoint's DBConnector must be non-null");
        }

        this.db = db;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
    }


    @Override
    public Message processMessage(Message msg) {
        if (msg == null) {//This should not happen
            LOGGER.severe("Trl.processMessage() received null message");
            return null;
        }

        //1. Check if this peer can observe
        String id = msg.getSenderId();
        if (id == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized peer: " + id);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }

        if (peerIdentitiesToNames != null) {
            id = peerIdentitiesToNames.get(id);
            if (id == null) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "unauthorized peer: " + id);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        }

        // peer is authorized to observe

        //2. Retrieve the pertaining tokens in the trlTable
        Set<String> pertainingTokens;
        try{
            pertainingTokens = db.getPertainingTokens(id);
        } catch(AceException e) {
            LOGGER.severe("Message processing aborted (getting tokens): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //3. Get the map cti-tokenhash from the database
        Map<String, String> ctiToTokenHash = null;
        try{
            ctiToTokenHash = db.getTokenHashMap();
        } catch(AceException e) {
            LOGGER.severe("Message processing aborted (getting token hashes from db): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //4. Create the cbor array containing the token hashes
        CBORObject hashes = CBORObject.NewArray();
        Set<String> tokenHashes = new HashSet<>();

        for (String tokenCti : pertainingTokens) {
            String tokenHash = ctiToTokenHash.get(tokenCti);
            if (tokenHash != null) {
                hashes.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));
                tokenHashes.add(tokenHash);
            }
        }
        LOGGER.log(Level.FINEST, "Returning hashes: " + tokenHashes);
        return msg.successReply(Message.CREATED, hashes);

    }

    @Override
    public void close() throws AceException {
        this.db.close();
    }
}
