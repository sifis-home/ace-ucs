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
     * The CBOR array containing the diff entries
     */
    private CBORObject diffSet;

    /**
     * The maximum size of the CBOR array containing the diff entries
     */
    private int maxSize;

    /**
     * The total number of insertions made in the CBOR array containing the diff entries,
     * i.e., the number of TRL updates occurred.
     */
    private int maxIndex;
    
    public DiffSet(int size) {
        this.maxSize = size;
        diffSet = CBORObject.NewArray();
        maxIndex = 0;
    }

    /**
     * Put a new diff entry in the diffSet CBOR array. The diff entry is a CBOR array
     * containing two CBOR arrays {@code removed} and {@code added} (inputs of this method).
     *
     * @param removed a CBOR array containing Byte Strings of token hashes that
     *                were revoked and are now expired
     * @param added a CBOR array containing Byte Strings of token hashes that
     *              have been revoked
     *
     * @throws AceException if the inputs are not CBOR arrays
     */
    public synchronized void pushDiffEntry(CBORObject removed, CBORObject added) throws AceException {

        if (added.getType() != CBORType.Array || removed.getType() != CBORType.Array) {
            throw new AceException("pushDiffEntry() requires inputs of type CBOR array");
        }
        CBORObject diffEntry = CBORObject.NewArray();
        diffEntry.Add(removed);
        diffEntry.Add(added);

        if (diffSet.size() == maxSize) {
            diffSet.RemoveAt(0);
            diffSet.Insert(maxSize-1, diffEntry);
        }
        else {
            diffSet.Add(diffEntry); // check if I can get rid of the else branch
        }
        maxIndex++;
    }


    /**
     * Select {@code u} diff entries from diffSet such that the last of these entries
     * is the {@code position}-th entry of diffSet.
     * Then, return a CBOR array containing the first {@code l} entries (of the {@code u})
     * in reverse order. That is, the diff entry at index 0 is the diff entry that
     * was added last among the set {@code l}.
     *
     * @param u the number of diff entries to select in the diffSet
     * @param l the number of diff entries to return
     * @param position the position (in the diffSet CBOR array)
     *                 of the last of the {@code u} diff entries to select
     *
     * @return a CBOR array containing the first {@code l} diff entries among the {@code u} selected.
     *
     * @throws AceException if the input value {@code u} is lower than {@code l}.
     */
    public CBORObject getDiffEntries(int u, int l, int position) throws AceException {
//        if (diffSet.size() == 0) {
//            // this should not happen since the Trl have to check it beforehand
//            // and return the combination empty,Null,False
//            return CBORObject.NewArray();
//        }
        if (u < 0 || l < 0) {
            throw new AceException("getDiffEntries() requires positive input parameters");
        }
        if (u < l) {
            // this should not happen. u can be at most equal to l.
            throw new AceException("getDiffEntries() requires the input parameter u " +
                    "to be greater than or equal to l.");
        }
        if (position > diffSet.size() || position < 1) {
            throw new AceException("getDiffEntries() requires the input parameter 'position' " +
                    "to be in the range [1,diffSet.size]");
        }
        if (position < u) {
            //trying to select more entries than the number of entries in the array
            throw new AceException("getDiffEntries() requires the input parameter 'u' to be" +
                    "lower than or equal to 'position'.");
        }
        int n = position - u + l; // n is the n-th element in the diffSet array, not its index
        return getDiffEntries(l, n);
    }


    /**
     * Select and return (in a CBOR array) {@code num} diff entries from the diffSet CBOR array.
     * The first element of the CBOR array returned, is the element in position {@code firstToReturn}
     * of the diffSet CBOR array. The second element of the CBOR array returned, is the element
     * in position {@code firstToReturn - 1} of the diffSet CBOR array, and so on.
     *
     * @param num the number of diff entries to return
     * @param firstToReturn the position, in the diffSet array, of most recent diff entry to return.
     *                      The first element is in position 1, and the n-th element is in position n.
     *                      This value does not refer to the array index.
     *
     * @return a CBOR array of {@code num} diff entries in reverse order w.r.t. the diffSet array.
     *         That is, the first element of the array is the element found at position {@code firstToReturn}
     *         in the diffSet array.
     * @throws AceException if the input value {@code num} is either non-negative or in range
     */
    public CBORObject getDiffEntries(int num, int firstToReturn) throws AceException {
        if (num > firstToReturn || num < 0) {
            throw new AceException("getDiffEntries() requires the input parameter 'num' " +
                    "to be non negative and in range. The maximum value allowed is equal to " +
                    "the size of the diffSet array");
        }
        CBORObject latestDiffEntries = CBORObject.NewArray();
        for (int i = 1; i <= num; i++) {
            latestDiffEntries.Add(diffSet.get(firstToReturn - i));
        }
        return latestDiffEntries;
    }


    /**
     *
     * Select the latest {@code u} diff entries from the diffSet array and return
     * the first {@code l} in reverse order in a CBOR array.
     *
     * @param u the number of diff entries to select in the diffSet
     * @param l the number of diff entries to return
     *
     * @return a CBOR array containing the eldest {@code l} diff entries among the {@code u} selected.
     * The first diff entry is the diff entry that was added last to the diffSet (among the set of {@code l}).
     *
     * @throws AceException if the input value {@code u} is lower than {@code l}.
     */
    public CBORObject getEldestDiffEntries(int u, int l) throws AceException {
        //int n = diffSet.size() - u + l; // n is the n-th element in the diffSet array, not its index
        //return getDiffEntries(l, n); // double check: was return getDiffEntries(n, l);
        return getDiffEntries(u, l, diffSet.size());
    }


    /**
     * Get the latest {@code u} diff entries from the diffSet array and return
     * them in reverse order in a CBOR array.
     *
     * @param u the number of diff entries to return
     *
     * @return a CBOR array containing the latest u diff entries. The first diff entry
     *         is the diff entry that was added last to the diffSet
     *
     * @throws AceException if the input value is either non-negative and in range
     */
    public CBORObject getLatestDiffEntries(int u) throws AceException {
        return getDiffEntries(u, u, diffSet.size());
    }


    /**
     * Get the current size of the diffSet CBOR array
     * @return the current size of the diffSet CBOR array
     */
    public int getSize() {
        return diffSet.size();
    }


    /**
     * Get the absolute number of insertion made in the diffSet CBOR array,
     * which corresponds to the latest index.
     * For example, if 10 insertions were made in diffSet, {@code maxIndex} value
     * is 10.
     *
     * @return the number of insertion made in the diffSet CBOR array.
     */
    public int getMaxIndex() {
        return maxIndex;
    }


    /**
     * Get the index of the oldest diff entry in the diffSet CBOR array.
     * The index refers to the absolute number of insertion made in the diffSet
     * CBOR array.
     * For example, if 10 insertions were made in diffSet, and its maximum size
     * is three, the oldest diff entry has index 8 since the 8-th, 9-th, and 10-th
     * inserted diff entries are currently in diffSet.
     *
     * @return the index of the oldest diff entry in the diffSet CBOR array.
     */
    public int getOldestIndex() {
        return maxIndex == 0 ? 0 : maxIndex - diffSet.size() + 1;
    }
}
