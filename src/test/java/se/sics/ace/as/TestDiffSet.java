package se.sics.ace.as;

import com.upokecenter.cbor.CBORObject;
import org.junit.*;
import se.sics.ace.AceException;
import se.sics.ace.Constants;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the DiffSet class
 *
 * @author Marco Rasori
 */

public class TestDiffSet {
    public static DiffSet diff = new DiffSet(5);


    /**
     * Utility function that simplifies the insertion of a diff
     * entry in the diffSet array.
     * It creates a diff entry that has 'removed' with value an empty
     * CBOR array, and 'added' with value a CBOR array containing the
     * input String.
     * It then pushes the diff entry into the diffSet.
     * @param tokenHash
     * @throws AceException
     */
    public void pushDummyDiffEntry(String tokenHash) throws AceException {
        CBORObject added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));
        diff.pushDiffEntry(CBORObject.NewArray(), added);
    }


    /**
     * Build a new DiffSet, push an entry at a time, and check that
     * the size of the diffSet array, maxIndex, and oldestIndex have
     * the expected value
     */
    @Test
    public void TestDiffSetSizeAndIndexes() throws Exception {
        diff = new DiffSet(5);

        // empty diffSet
        assert(diff.getSize() == 0);
        assert(diff.getMaxIndex() == 0);
        assert(diff.getOldestIndex() == 0);

        // 1st insertion
        pushDummyDiffEntry("th1");
        assert(diff.getSize() == 1);
        assert(diff.getMaxIndex() == 1);
        assert(diff.getOldestIndex() == 1);

        // 2nd insertion
        pushDummyDiffEntry("th2");
        assert(diff.getSize() == 2);
        assert(diff.getMaxIndex() == 2);
        assert(diff.getOldestIndex() == 1);

        // 3rd insertion
        pushDummyDiffEntry("th3");
        assert(diff.getSize() == 3);
        assert(diff.getMaxIndex() == 3);
        assert(diff.getOldestIndex() == 1);

        // 4th insertion
        pushDummyDiffEntry("th4");
        assert(diff.getSize() == 4);
        assert(diff.getMaxIndex() == 4);
        assert(diff.getOldestIndex() == 1);

        // 5th insertion
        pushDummyDiffEntry("th5");
        assert(diff.getSize() == 5);
        assert(diff.getMaxIndex() == 5);
        assert(diff.getOldestIndex() == 1);

        // 6th insertion
        pushDummyDiffEntry("th6");
        assert(diff.getSize() == 5);
        assert(diff.getMaxIndex() == 6);
        assert(diff.getOldestIndex() == 2);

        // 7th insertion
        pushDummyDiffEntry("th7");
        assert(diff.getSize() == 5);
        assert(diff.getMaxIndex() == 7);
        assert(diff.getOldestIndex() == 3);

        // 8th insertion
        pushDummyDiffEntry("th8");
        assert(diff.getSize() == 5);
        assert(diff.getMaxIndex() == 8);
        assert(diff.getOldestIndex() == 4);
    }

    /**
     * Try to get the latest 3 diff entries from an empty diffSet
     * It will throw an exception
     * @throws AceException
     */
    @Test
    public void TestGetDiffEntries() throws AceException {
        diff = new DiffSet(5);

        CBORObject diffEntries;
        try {
            diffEntries = diff.getLatestDiffEntries(3);
        } catch (AceException e) {
            diffEntries = CBORObject.NewArray();
        }
    }

    /**
     * Try to get the latest 3 diff entries from an empty diffSet
     * Check the exception
     * @throws AceException
     */
    @Test
    public void TestFailGetLatestDiffEntriesWhenSizeIsLowerThanTheRequestedNumberOfEntries() throws AceException {
        diff = new DiffSet(5);
        AceException exception = assertThrows(AceException.class,
                () -> diff.getLatestDiffEntries(3));
        assertTrue(exception.getMessage().contains("getDiffEntries() requires the input parameter 'position' " +
                "to be in the range [1,diffSet.size]"));
//        exceptionRule.expect(AceException.class);
//        exceptionRule.expectMessage("getDiffEntries() requires the input parameter 'position' " +
//                "to be in the range [1,diffSet.size]");
//
//
//        diff.getLatestDiffEntries(3);
    }

    /**
     * get the latest diff entries from the diffSet. The input
     * has to be lower than or equal to the size of the diffSet.
     * Finally, specify a number higher than the size, and get the exception
     *
     * @throws AceException
     */
    @Test
    public void TestGetLatestDiffEntries() throws AceException {

        diff = new DiffSet(5);
        pushDummyDiffEntry("th1");

        CBORObject diffEntries;
        diffEntries = diff.getLatestDiffEntries(0);
        assert(diffEntries.size() == 0);

        diffEntries = diff.getLatestDiffEntries(1);
        assert(diffEntries.size() == 1);

        // cannot obtain 2 diff entries. The diffSet array has size 1.
        AceException exception = assertThrows(AceException.class,
                () -> diff.getLatestDiffEntries(2));
        assertTrue(exception.getMessage().contains("getDiffEntries() requires the input parameter 'u' to be " +
                "lower than or equal to 'position'."));
    }

    /**
     * Test the getEldestDiffEntries method while incrementally pushing
     * diff entries in the diffSet.
     * Verify that the returned diff entries are correct and in reverse order
     *
     * @throws AceException
     */
    @Test
    public void TestGetEldestDiffEntries() throws AceException {
        diff = new DiffSet(5);
        pushDummyDiffEntry("th1");

        CBORObject diffEntries;
        diffEntries = diff.getEldestDiffEntries(0, 0);
        assert(diffEntries.size() == 0);

        diffEntries = diff.getEldestDiffEntries(1, 0);
        assert(diffEntries.size() == 0);

        diffEntries = diff.getEldestDiffEntries(1, 1);
        assert(diffEntries.size() == 1);

        pushDummyDiffEntry("th2");
        diffEntries = diff.getEldestDiffEntries(2, 1);
        assert(diffEntries.size() == 1);

        diffEntries = diff.getEldestDiffEntries(2, 1);
        assert(diffEntries.size() == 1);
        // the first diff entry should contain "th1"
        assert(new String(diffEntries.get(0).get(1).get(0).GetByteString(), Constants.charset).equals("th1"));

        diffEntries = diff.getEldestDiffEntries(2, 2);
        assert(diffEntries.size() == 2);
        // the first diff entry should contain "th2"
        assert(new String(diffEntries.get(0).get(1).get(0).GetByteString(), Constants.charset).equals("th2"));
        // the second diff entry should contain "th1"
        assert(new String(diffEntries.get(1).get(1).get(0).GetByteString(), Constants.charset).equals("th1"));

        pushDummyDiffEntry("th3");
        pushDummyDiffEntry("th4");
        pushDummyDiffEntry("th5");
        pushDummyDiffEntry("th6");
        pushDummyDiffEntry("th7");
        pushDummyDiffEntry("th8");

        diffEntries = diff.getEldestDiffEntries(4, 2);
        // the first diff entry should contain "th2"
        assert(new String(diffEntries.get(0).get(1).get(0).GetByteString(), Constants.charset).equals("th6"));
        // the second diff entry should contain "th1"
        assert(new String(diffEntries.get(1).get(1).get(0).GetByteString(), Constants.charset).equals("th5"));
    }

    /**
     * Test the getDiffEntries method while incrementally pushing
     * diff entries in the diffSet.
     * Verify that the returned diff entries are correct and in reverse order
     *
     * @throws AceException
     */
    @Test
    public void TestGetDiffEntriesWithPosition() throws AceException {
        diff = new DiffSet(5);
        pushDummyDiffEntry("th1");

        CBORObject diffEntries;
        diffEntries = diff.getDiffEntries(1, 0, 1);
        assert(diffEntries.size() == 0);

        pushDummyDiffEntry("th2");
        pushDummyDiffEntry("th3");
        pushDummyDiffEntry("th4");
        pushDummyDiffEntry("th5");
        pushDummyDiffEntry("th6");
        pushDummyDiffEntry("th7");
        pushDummyDiffEntry("th8");

        // select 3 diff entries backward in the array, starting from the 4th
        // diff entry (the diff entry in position 4).
        // Then, take the first two of these 3 entries and return them in reverse order

        // [th4][th5][th6][th7][th8]<== representation of diffSet array after insertions
        //                  ^========== start from position 4
        //      |_____________| <====== go backward 3 entries
        //      |_________|     <====== select the first 2 entries
        //      [th6][th5]      <====== reverse the order

        // Note that this is just a simplified representation of diffSet. In the actual implementation,
        // a diff entries is composed of two arrays:
        // [[array1],[array2]]  <= this is just one diff entry, represented above, for example, as [th1].

        diffEntries = diff.getDiffEntries(3, 2, 4);
        // the first diff entry should contain "th6"
        assert(new String(diffEntries.get(0).get(1).get(0).GetByteString(), Constants.charset).equals("th6"));
        // the second diff entry should contain "th5"
        assert(new String(diffEntries.get(1).get(1).get(0).GetByteString(), Constants.charset).equals("th5"));

    }
}

