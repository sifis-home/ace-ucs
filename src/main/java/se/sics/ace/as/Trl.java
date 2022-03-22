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
     * The query parameters of the current request
     */
    private Map<String,Integer> queryParameters = new HashMap<>();

    /**
     * true if the current request has the observe option set
     */
    private boolean hasObserve = false;

    /**
     * Pre-defined positive integer. The maximum number of diff-entries stored per peer.
     * It determines the maximum size of the array 'diffSet' in a DiffSet object.
     */
    private int nMax;

    /**
     * Map between peer ids and their DiffSets representing their portion of trl
     */
    private Map<String, DiffSet> DiffSetsMap;


    /**
     * Constructor.
     *
     * @param db  the database connector
     * @param peerIdentitiesToNames  mapping between security identities
     *                               of the peers and their names; it can be null
     * @param nMax
     *
     * @throws AceException  if the db connector is null
     */
    public Trl(DBConnector db,
               Map<String, String> peerIdentitiesToNames,
               int nMax)
            throws AceException {

        if (db == null) {
            LOGGER.severe("Trl endpoint's DBConnector was null");
            throw new AceException(
                    "Trl endpoint's DBConnector must be non-null");
        }

        if (nMax <= 0) {
            LOGGER.severe("nMax value not allowed.");
            throw new AceException("nMax MUST be a positive integer");
        }

        this.db = db;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
        this.nMax = nMax;

        // Initialize a DiffSet structure for each known peer, i.e., for each registered device.
        Set<String> knownRss = db.getRSS();
        if (knownRss == null)  knownRss = new HashSet<>();
        Set<String> knownIds = db.getClients();
        if (knownIds == null)  knownIds = new HashSet<>();
        knownIds.addAll(knownRss);

        this.DiffSetsMap = new HashMap<>();
        for (String id : knownIds) {
            this.DiffSetsMap.put(id, new DiffSet(nMax));
        }
    }


    @Override
    public synchronized Message processMessage(Message msg) {
        if (msg == null) {//This should not happen
            LOGGER.severe("Trl.processMessage() received null message");
            return null;
        }

        // Check if this peer can make requests
        String id = msg.getSenderId();
        if (id == null) {
            CBORObject errorMap = errorUnauthorizedPeer(id);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, errorMap);
        }

        if (peerIdentitiesToNames != null) {
            id = peerIdentitiesToNames.get(id);
            if (id == null) {
                CBORObject errorMap = errorUnauthorizedPeer(id);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, errorMap);
            }
        }

        // Check the validity of query parameters
        CBORObject errorMap = checkQueryParameters();
        if (errorMap != null) {
            return msg.failReply(Message.FAIL_BAD_REQUEST, errorMap);
        }

        if (queryParameters.containsKey("pmax")) {
            // set the time between this and the next response
            // FIXME: cannot find "pmax" or "maximum period" in Californium code
        }

        if (queryParameters.containsKey("diff")) {
            // Process a diff-query request
            return processDiffQuery(msg, id);
        }
        else {
            // Process a full-query request
            return processFullQuery(msg, id);
        }
    }

    private Message processDiffQuery(Message msg, String id) {

        //1. Get the number of diff-entries to return
        int num = queryParameters.get("diff");
        if (num == 0 || num > this.nMax) {
            num = this.nMax;
        }

        int size = DiffSetsMap.get(id).getSize(); // actual size of the diffSet array of the peer
        int u = size < num ? size : num;
                //min(size,num);

        //2. Create the CBOR array containing the diff-entries
        CBORObject diffSet;
        try {
            diffSet = DiffSetsMap.get(id).getLatestDiffEntries(u);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (getting latest diff entries): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //3. Create the map containing the diff set, cursor value, and more value
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, diffSet);

        int cursor = DiffSetsMap.get(id).getMaxIndex();
        if (cursor == 0) {
            map.Add(Constants.CURSOR, CBORObject.Null);
        }
        else {
            map.Add(Constants.CURSOR, cursor);
        }

        // placeholder. To edit when the logic for the third mode will be implemented
        map.Add(Constants.MORE, CBORObject.False);

        LOGGER.log(Level.FINEST, "Returning diff set CBOR array");
        return msg.successReply(Message.CONTENT, map);
    }


    private Message processFullQuery(Message msg, String id) {

        //1. Retrieve the pertaining tokens in the trlTable
        Set<String> pertainingTokens;
        try{
            pertainingTokens = db.getPertainingTokens(id);
        } catch(AceException e) {
            LOGGER.severe("Message processing aborted (getting tokens): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //2. Get the map cti-tokenhash from the database
        Map<String, String> ctiToTokenHash = null;
        try{
            ctiToTokenHash = db.getTokenHashMap();
        } catch(AceException e) {
            LOGGER.severe("Message processing aborted (getting token hashes from db): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //3. Create the CBOR array containing the token hashes as Byte Strings
        CBORObject fullSet = CBORObject.NewArray();
        Set<String> tokenHashes = new HashSet<>();

        for (String tokenCti : pertainingTokens) {
            String tokenHash = ctiToTokenHash.get(tokenCti);
            if (tokenHash != null) {
                fullSet.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));
                tokenHashes.add(tokenHash);
            }
        }

        //3. Create the map containing the full set and cursor value
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.FULL_SET, fullSet);

        int cursor = DiffSetsMap.get(id).getMaxIndex();
        if (cursor == 0) {
            map.Add(Constants.CURSOR, CBORObject.Null);
        }
        else {
            map.Add(Constants.CURSOR, cursor);
        }

        LOGGER.log(Level.FINEST, "Returning full set: " + tokenHashes);
        return msg.successReply(Message.CONTENT, map);
    }



    public void setQueryParameters(Map<String,Integer> queryParameters) {
        this.queryParameters = new HashMap<>(queryParameters);
    }

    public void setHasObserve(boolean observe) {
        this.hasObserve = observe;
    }


    private CBORObject checkQueryParameters() {

        // accepted parameters:
        // pmax:  Maximum time, in seconds, between two consecutive notifications
        //        for the observation.
        //        It makes sense only for observe request, and its value MUST be
        //        greater than zero.
        // diff:  If included, it indicates to perform a diff query of the
        //        TRL.  Its value MUST be either:
        //         -  the integer 0, indicating that a (notification) response should
        //            include as many diff entries as the Authorization Server can
        //            provide in the response; or
        //         -  a positive integer greater than 0, indicating the maximum
        //            number of diff entries that a (notification) response should
        //            include.
        // cursor: The index of the first diff-entry to return.
        //         Its value MUST be either greater than or equal to zero.
        //         If included, also 'diff' parameter MUST be present.

        Integer n = queryParameters.get("diff");
        if (n != null && n < 0) { // diff specified and lower than 0
            return errorInvalidParameterValue();
        }

        if (!this.hasObserve) {
            queryParameters.remove("pmax"); // ignore pmax if not observe
        }
        Integer pmax = queryParameters.get("pmax");
        if (pmax != null && pmax <= 0) { // pmax specified and lower than or equal to 0
            return errorInvalidParameterValue();
        }

        Integer p = queryParameters.get("cursor");

        if (p!= null && n == null) { // cursor specified but diff not specified
            return errorInvalidSetOfParametersMap();
        }

        if (p != null && p < 0) {
            // cursor specified and lower than 0
            return errorInvalidParameterValue();
        }

        // return null if all the checks passed
        return null;
    }


    /**
     * Build a CBOR map containing the error 'invalid parametr value' to return as response
     *
     * @return the map containing the error and error_description
     */
    private CBORObject errorInvalidParameterValue() {
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.TRL_ERROR,
                Constants.INVALID_PARAMETER_VALUE);
        map.Add(Constants.TRL_ERROR_DESCRIPTION,
                Constants.INVALID_PARAMETER_VALUE_DESCRIPTION);
        LOGGER.log(Level.INFO, "Message processing aborted: "
                + Constants.INVALID_PARAMETER_VALUE_DESCRIPTION);
        return map;
    }


    /**
     * Build a CBOR map containing the error 'invalid set of parameters' to return as response
     *
     * @return the map containing the error and error_description
     */
    private CBORObject errorInvalidSetOfParametersMap() {
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.TRL_ERROR,
                Constants.INVALID_SET_OF_PARAMETERS);
        map.Add(Constants.TRL_ERROR_DESCRIPTION,
                Constants.INVALID_SET_OF_PARAMETERS_DESCRIPTION);
        LOGGER.log(Level.INFO, "Message processing aborted: "
                + Constants.INVALID_SET_OF_PARAMETERS_DESCRIPTION);
        return map;
    }


    /**
     * Build a CBOR map containing the error 'unauthorized client' to return as response
     *
     * @return the map containing the error
     */
    private CBORObject errorUnauthorizedPeer(String id) {
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        LOGGER.log(Level.INFO, "Message processing aborted: "
                + "unauthorized peer: " + id);
        return map;
    }


    /**
     *
     * @return a reference to the DiffSetMap to be used by the RevocationHandler
     */
    public Map<String, DiffSet> getDiffSetsMap() {
        return this.DiffSetsMap;
    }


    public void addPeerToDiffSetsMap(String id) {
        this.DiffSetsMap.put(id, new DiffSet(this.nMax));
    }


    @Override
    public void close() throws AceException {
        this.db.close();
    }
}
