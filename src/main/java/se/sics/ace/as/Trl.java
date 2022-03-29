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
     * Pre-defined positive integer. The maximum number of diff entries stored per peer.
     * It determines the maximum size of the array 'diffSet' in a DiffSet object.
     */
    private int nMax;

    /**
     * Maximum number of diff entries that the AS can include in a diff query response
     */
    private int maxDiffBatch;

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
     * @param nMax maximum number of diff entries stored per peer.
     * @param maxDiffBatch maximum number of diff entries that the AS can include
     *                     in a diff query response. It can be null, and, in that case,
     *                     its value is set to the value of nMax
     *
     * @throws AceException if the db connector is null, nMax and maxDiffBatch
     *                      are lower than or equal to zero.
     */
    public Trl(DBConnector db,
               Map<String, String> peerIdentitiesToNames,
               int nMax, Integer maxDiffBatch)
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
        if (maxDiffBatch == null) {
            this.maxDiffBatch = nMax;
        }
        else if (maxDiffBatch <= 0) {
            LOGGER.severe("maxDiffBatch value not allowed.");
            throw new AceException("maxDiffBatch MUST be a positive integer or null.");
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

            // Empty collection (Appendix B.4.1)
            if (DiffSetsMap.get(id).getMaxIndex() == 0) {
                return processDiffQueryEmptyCollection(msg);
            }

            if (queryParameters.containsKey("cursor")) {
                // Cursor Specified in the Diff Query Request (Appendix B.4.3)
                return processDiffQueryWithCursor(msg, id);
            }
            else {
                // Cursor Not Specified in the Diff Query Request (Appendix B.4.2)
                return processDiffQueryNoCursor(msg, id);
            }
        }
        else {
            // Process a full-query request
            return processFullQuery(msg, id);
        }
    }


    private Message processDiffQueryEmptyCollection(Message msg) {
        CBORObject map = CBORObject.NewMap();

        map.Add(Constants.DIFF_SET, CBORObject.NewArray());
        map.Add(Constants.CURSOR, CBORObject.Null);
        map.Add(Constants.MORE, CBORObject.False);

        LOGGER.log(Level.FINEST, "Returning diff query Empty Collection");
        return msg.successReply(Message.CONTENT, map);
    }


    private Message processDiffQueryNoCursor(Message msg, String id) {

        //1. Get the number of diff entries to return
        int num = queryParameters.get("diff");
        if (num == 0 || num > this.nMax) {
            num = this.nMax;
        }

        int size = DiffSetsMap.get(id).getSize(); // actual size of the diffSet array of the peer
        int u = size < num ? size : num;
        //min(size,num);

        int l = u < maxDiffBatch ? u : maxDiffBatch;
        //min(u,maxDiffBatch);

        //2. Create the CBOR array containing the diff entries
        CBORObject diffSet;
        try {
            if (u <= maxDiffBatch) {
                diffSet = DiffSetsMap.get(id).getLatestDiffEntries(u);
            }
            else {
                diffSet = DiffSetsMap.get(id).getEldestDiffEntries(u, l);
            }
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (getting diff entries): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //3. Create the map containing the diff set, cursor value, and more value
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, diffSet);

        int cursor = DiffSetsMap.get(id).getMaxIndex() + u - l;
        map.Add(Constants.CURSOR, cursor);

        if (u <= maxDiffBatch) {
            map.Add(Constants.MORE, CBORObject.False);
        }
        else {
            map.Add(Constants.MORE, CBORObject.True);
        }

        LOGGER.log(Level.FINEST, "Returning diff set CBOR map");
        return msg.successReply(Message.CONTENT, map);
    }


    private Message processDiffQueryWithCursor(Message msg, String id) {

        int p = queryParameters.get("cursor");
        int lastIndex = DiffSetsMap.get(id).getMaxIndex();
        if (p > lastIndex) {
            // the requester deliberately specified a wrong value of 'cursor'
            CBORObject errorMap = errorOutOfBoundCursorValueMap(id);
            return msg.failReply(Message.FAIL_BAD_REQUEST, errorMap);
        }

        int oldestIndex = DiffSetsMap.get(id).getOldestIndex();
        //if (p + 1 >= oldestIndex && p + 1 <= lastIndex) { // oldestIndex <= p + 1 <= lastIndex
        // if (p < oldestIndex && p + 1 < oldestIndex) {
        if (p + 1 < oldestIndex) {
            // the index the requester specified in 'cursor' is obsolete
            // (too old and therefore removed from the diffSet array)
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.DIFF_SET, CBORObject.NewArray());
            map.Add(Constants.CURSOR, CBORObject.Null);
            map.Add(Constants.MORE, CBORObject.True);

            LOGGER.log(Level.FINEST, "Returning diff set CBOR map (specified cursor was obsolete)");
            return msg.successReply(Message.CONTENT, map);
        }

        // if (p >= oldestIndex - 1 && p <= lastIndex)
        // is the condition for which we should continue processing, and this means
        // that p is in the range [oldestIndex-1, lastIndex] and the request is legit.

        //1. Get the number of diff entries to return
        int num = queryParameters.get("diff");
        if (num == 0 || num > this.nMax) {
            num = this.nMax;
        }

        int subSize = lastIndex - p;
        int size = DiffSetsMap.get(id).getSize();
        assert(subSize <= size);

        int subU = subSize < num ? subSize : num;
        //min(subSize,num);

        int l = subU < maxDiffBatch ? subU : maxDiffBatch;

        //2. Create the CBOR array containing the diff entries
        CBORObject diffSet;
        try {
            int fromArrayPosition = size - (lastIndex - (p + subU));
            diffSet = DiffSetsMap.get(id).getDiffEntries(subU, l, fromArrayPosition);

        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (getting diff entries): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

        //3. Create the map containing the diff set, cursor value, and more value
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, diffSet);

        int cursor = p + l;
        map.Add(Constants.CURSOR, cursor);

        if (subU <= maxDiffBatch) {
            map.Add(Constants.MORE, CBORObject.False);
        }
        else {
            map.Add(Constants.MORE, CBORObject.True);
        }

        LOGGER.log(Level.FINEST, "Returning diff set CBOR map");
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


    /**
     * Check compliance of query parameters. Note that this check is done on the
     * "general shape" of query parameters; they are not checked against the values
     * of the specific instance of the DiffSet structure.
     * For example, here the 'cursor' value is checked to be not lower than zero.
     * It is not checked whether its value is lower than the latest TRL update (maxIndex)
     * in the DiffSet structure of the specific peer.
     *
     * @return a map containing an error if one or more query parameters are not
     *         compliant with the specification, null otherwise
     */
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
        // cursor: The index of the first diff entry to return.
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
     * Build a CBOR map containing the error 'out of bound cursor value' to return as response.
     * The map contains also the cursor with value the maxIndex, i.e., the last trl update
     * for the peer
     *
     * @return the map containing the error and error_description
     */
    private CBORObject errorOutOfBoundCursorValueMap(String id) {
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.TRL_ERROR,
                Constants.OUT_OF_BOUND_CURSOR_VALUE);
        map.Add(Constants.TRL_ERROR_DESCRIPTION,
                Constants.OUT_OF_BOUND_CURSOR_VALUE_DESCRIPTION);
        map.Add(Constants.CURSOR, DiffSetsMap.get(id).getMaxIndex());
        LOGGER.log(Level.INFO, "Message processing aborted: "
                + Constants.OUT_OF_BOUND_CURSOR_VALUE_DESCRIPTION);
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
