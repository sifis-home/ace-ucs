package se.sics.ace.coap.client;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TrlStore;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Simple TrlStore that can process full-query and diff-query responses.
 *
 * When processing a full-query response, it replaces the local trl with the
 * set of all the token hashes included in the response (a full-query response
 * gives the most recent and complete snapshot of the trl for the peer).
 *
 * When processing a diff-query response, it builds two sets of 'removed' and
 * 'added' token hashes. It then first makes the union of the local trl with
 * the 'added' set and then subtracts the 'removed' set.
 *
 * @author Marco Rasori
 */
public class BasicTrlStore implements TrlStore {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(BasicTrlStore.class.getName());


    /**
     * structure containing revoked token hashes
     */
    public Set<String> localTrl = new HashSet<>();

    public int cursor;
    public boolean more;

    @Override
    public void updateLocalTrl(CBORObject payload) throws AceException {
        if (payload.getType() != CBORType.Map) {
            throw new AceException("Error processing trl response. " +
                    "Expected type is CBOR map.");
        }
        Map<Short, CBORObject> map = Constants.getParams(payload);
        if (map.containsKey(Constants.FULL_SET)) {
            processFullQuery(payload);
        }
        else if (map.containsKey(Constants.DIFF_SET)) {
            processDiffQuery(payload);
        }
        else {
            throw new AceException("Error processing trl response. " +
                    "No CBOR array FULL_SET or DIFF_SET found within the CBOR map.");
        }
    }


    /**
     * Process the payload of a full query response.
     * If the payload is a CBOR map, first update the cursor value and then process
     *
     * @param payload CBOR object being a CBOR map or a CBOR array
     * @throws AceException if the CBOR map cannot be parsed
     */
    @Override
    public void processFullQuery(CBORObject payload)
            throws AceException {

        if (payload.getType() != CBORType.Map) {
            throw new AceException("Error processing full query response. " +
                    "Expected type is CBOR map.");
        }

        Map<Short, CBORObject> map = Constants.getParams(payload);
        if (!map.containsKey(Constants.FULL_SET)) {
            throw new AceException("Error processing full query response. " +
                    "No CBOR array FULL_SET found within the CBOR map.");
        }

        if (map.containsKey(Constants.CURSOR)) {
            if (map.get(Constants.CURSOR).equals(CBORObject.Null)) {
                cursor = 0;
            }
            else {
                cursor = map.get(Constants.CURSOR).AsNumber().ToInt32Checked();
            }
        }

        processFullSetArray(map.get(Constants.FULL_SET));
    }

    /**
     * Replace the content of the local trl with the set of token hashes
     * found in the CBOR array passed as input
     *
     * @param fullSet the CBOR array containing the token hashes encoded as byte strings
     */
    private void processFullSetArray(CBORObject fullSet) throws AceException {

        if (fullSet.getType() != CBORType.Array) {
            throw new AceException("Error processing full query response. " +
                    "Expected type is CBOR array.");
        }

        if (fullSet.size() != 0 && fullSet.get(0).getType() != CBORType.ByteString) {
            throw new AceException("Error processing full query response. " +
                    "CBOR array does not contain Byte Strings.");
        }

        Set<String> hashes = new HashSet<>();
        for (int i = 0; i < fullSet.size(); i++) {
            byte[] tokenHashB = fullSet.get(i).GetByteString();
            String tokenHashS = new String(tokenHashB, Constants.charset);
            hashes.add(tokenHashS);
        }
        LOGGER.info("Set of received token hashes: " + hashes);

        localTrl = new HashSet<>(hashes);
    }

    /**
     * Process the payload of a diff query response.
     * If the payload is a CBOR map, first update the values of cursor and more, and then process
     *
     * @param payload CBOR object being a CBOR map or a CBOR array
     * @throws AceException if the CBOR map cannot be parsed
     */
    @Override
    public void processDiffQuery(CBORObject payload)
            throws AceException {

        if (payload.getType() != CBORType.Map) {
            throw new AceException("Error processing diff query response. " +
                    "Expected type is CBOR map.");
        }

        Map<Short, CBORObject> map = Constants.getParams(payload);
        if (!map.containsKey(Constants.DIFF_SET)) {
            throw new AceException("Error processing diff query response. " +
                    "No CBOR array DIFF_SET found within the CBOR map.");
        }

        if (map.containsKey(Constants.CURSOR)) {
            if (map.get(Constants.CURSOR).equals(CBORObject.Null)) {
                cursor = 0;
            }
            else {
                cursor = map.get(Constants.CURSOR).AsNumber().ToInt32Checked();
            }
        }

        if (map.containsKey(Constants.MORE)) {
            more = map.get(Constants.MORE).AsBoolean();
        }

        processDiffSetArray(map.get(Constants.DIFF_SET));
    }

    /**
     * Add to the local trl all the token hashes found in the trl-patch 'added',
     * and then remove from the local trl all the token hashes found in the trl-patch 'removed'.
     *
     * @param diffSet the CBOR array containing the diff-entries. Each diff-entry is a CBOR Array
     *                containing two arrays of byte strings called trl-patch. The trl-patch at index 0
     *                refers to the 'removed' token hashes, while the trl-patch at index 1 refers to
     *                the 'added' token hashes. A trl-patch is an array of byte strings, each of which
     *                is the representation of a token hash.
     */
    private void processDiffSetArray(CBORObject diffSet) throws AceException {

        if (diffSet.getType() != CBORType.Array) {
            throw new AceException("Error processing full query response. " +
                    "Expected type is CBOR array.");
        }

        if (diffSet.size() != 0 && diffSet.get(0).getType() != CBORType.Array) {
            throw new AceException("Error processing diff query response. " +
                    "CBOR array does not contain a CBOR Array.");
        }

        Set<String> removedTokenHashes = new HashSet<>();
        Set<String> addedTokenHashes = new HashSet<>();
        for (int index = 0; index < diffSet.size(); index++) {
            parseTrlPatch(diffSet.get(index).get(0), removedTokenHashes);
            parseTrlPatch(diffSet.get(index).get(1), addedTokenHashes);
        }

        localTrl.addAll(addedTokenHashes);
        localTrl.removeAll(removedTokenHashes);

        LOGGER.info("Set of token hashes added to the trl: " + addedTokenHashes + "\n" +
                    "Set of token hashes removed from the trl: " + removedTokenHashes);
    }

    /**
     * Extract token hashes as String from a CBOR array of byte strings, i.e., the trl-patch
     *
     * @param trlPatch the CBOR array containing byte strings
     * @param tokenHashes the set of token hashes extracted from the trl-patch
     */
    private void parseTrlPatch(CBORObject trlPatch, Set<String> tokenHashes) {
        for (int i = 0; i < trlPatch.size(); i++) {
            byte[] tokenHashB = trlPatch.get(i).GetByteString();
            String tokenHashS = new String(tokenHashB, Constants.charset);
            tokenHashes.add(tokenHashS);
        }
    }

    /**
     * Get the content of the local trl
     *
     * @return the local trl
     */
    @Override
    public Set<String> getLocalTrl() {
        return new HashSet<>(localTrl);
    }

    /**
     * Get the cursor value
     *
     * @return the cursor value
     */
    @Override
    public int getCursorValue() {
        return cursor;
    }
}

