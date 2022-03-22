package se.sics.ace.as;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import se.sics.ace.AceException;

import java.util.logging.Logger;

public class DiffSet {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(DiffSet.class.getName() );

    /**
     * The CBOR array containing the diff-entries
     */
    private CBORObject diffSet;

    /**
     * The maximum size of the CBOR array containing the diff-entries
     */
    private int maxSize;

    /**
     * The total number of insertions made in the CBOR array containing the diff-entries
     */
    private int maxIndex;
    
    public DiffSet(int size) {
        this.maxSize = size;
        diffSet = CBORObject.NewArray();
        maxIndex = 0;
    }

    /**
     * Put a new diff-entry in the diffSet CBOR array. The diff-entry is a CBOR array
     * containing two CBOR arrays (the inputs of this method).
     *
     * @param removed a CBOR array containing byte strings of token hashes that
     *                were revoked and are now expired
     * @param added a CBOR array containing byte strings of token hashes that
     *              have been revoked
     *
     * @throws AceException if the inputs are not CBOR arrays
     */
    public void pushDiffEntry(CBORObject removed, CBORObject added) throws AceException {

        if (added.getType() != CBORType.Array || removed.getType() != CBORType.Array) {
            throw new AceException("pushDiffEntry() requires input of type CBOR array");
        }
        CBORObject diffEntry = CBORObject.NewArray();
        diffEntry.Add(removed);
        diffEntry.Add(added);

        if (diffSet.size() == this.maxSize) {
            diffSet.RemoveAt(0);
            diffSet.Insert(maxSize-1, diffEntry);
        }
        else {
            diffSet.Add(diffEntry); // check if I can get rid of the else branch
        }
        maxIndex++;
    }

    /**
     * Extract the latest u diff-entries from the diffSet and return a CBOR array
     * containing these entries in reverse order. That is, the diff-entry at index 0
     * is the diff-entry that was added last to the diffSet
     *
     * @param u the number of diff-entries to return
     *
     * @return a CBOR array containing the latest u diff-entries. The first diff-entry
     *         is the diff-entry that was added last to the diffSet
     *
     * @throws AceException if the input value is either non-negative and in range
     */
    public CBORObject getLatestDiffEntries(int u) throws AceException {
        if (u > diffSet.size() || u < 0) {
            throw new AceException("getLatestDiffEntries() requires the input parameter u " +
                    "to be non negative and in range. The maximum value allowed is equal to " +
                    "the size of the diffSet array");
        }
        CBORObject latestDiffEntries = CBORObject.NewArray();
        for (int i = 1; i <= u; i++) {
            latestDiffEntries.Add(diffSet.get(diffSet.size() - i));
        }
        return latestDiffEntries;
    }

    public int getSize() {
        return diffSet.size();
    }

    public int getMaxIndex() {
        return maxIndex;
    }
}
