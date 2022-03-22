package se.sics.ace;

import com.upokecenter.cbor.CBORObject;
import se.sics.ace.AceException;

import java.util.Set;

/**
 * The interface for a TrlStore.
 * A TrlStore should implement the methods to parse payloads extracted
 * from successful responses obtained from the trl endpoint.
 * The TrlStore should store in a 'local trl', the set of token hashes
 * of tokens known to be revoked.
 * The local trl should be updated as a consequence of the processing
 * of a trl response, whose decoded payload is passed to some methods
 * of this class.
 * Nonetheless, an implementation of the TrlStore could provide other
 * methods to update the local trl according to specific needs.
 *
 * @author Marco Rasori
 */
public interface TrlStore {


    void updateLocalTrl(CBORObject payload) throws AceException;

    /**
     * Process the payload of a response from the trl endpoint following a full-query request
     * @param payload the payload, extracted and decoded from bytes, of the response
     * @throws AceException
     */
    void processFullQuery(CBORObject payload) throws AceException;

    /**
     * Process the payload of a response from the trl endpoint following a diff-query request
     * @param payload the payload, extracted and decoded from bytes, of the response
     * @throws AceException
     */
    void processDiffQuery(CBORObject payload) throws AceException;

    /**
     * Get the set of token hashes currently in the local trl
     * @return the set of token hashes in the local trl
     */
    Set<String> getLocalTrl();

    /**
     * Get the cursor value
     * @return the cursor value
     */
    int getCursorValue();

}
