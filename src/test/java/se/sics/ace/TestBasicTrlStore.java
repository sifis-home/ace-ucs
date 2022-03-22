package se.sics.ace;

import com.upokecenter.cbor.CBORObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import se.sics.ace.as.DiffSet;
import se.sics.ace.coap.client.BasicTrlStore;

import java.util.HashSet;
import java.util.Set;

public class TestBasicTrlStore {

    private static DiffSet diffSetObj;
    private static CBORObject fullSetArray;

    @BeforeClass
    public static void setUp() throws AceException{
        diffSetObj = new DiffSet(3);

        CBORObject removed = CBORObject.NewArray();
        removed.Add(CBORObject.FromObject("th1".getBytes(Constants.charset)));
        removed.Add(CBORObject.FromObject("th2".getBytes(Constants.charset)));

        CBORObject added = CBORObject.NewArray();

        diffSetObj.pushDiffEntry(removed, added);

        removed = CBORObject.NewArray();

        added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject("th3".getBytes(Constants.charset)));
        added.Add(CBORObject.FromObject("th4".getBytes(Constants.charset)));

        diffSetObj.pushDiffEntry(removed, added);

        removed = CBORObject.NewArray();
        removed.Add(CBORObject.FromObject("th3".getBytes(Constants.charset)));

        added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject("th5".getBytes(Constants.charset)));
        added.Add(CBORObject.FromObject("th6".getBytes(Constants.charset)));

        diffSetObj.pushDiffEntry(removed, added);

        fullSetArray = CBORObject.NewArray();
        fullSetArray.Add(CBORObject.FromObject("th1".getBytes(Constants.charset)));
        fullSetArray.Add(CBORObject.FromObject("th6".getBytes(Constants.charset)));
        fullSetArray.Add(CBORObject.FromObject("th8".getBytes(Constants.charset)));

    }

    @AfterClass
    public static void tearDown(){}


    @Test
    public void testProcessDiffQueryResponse() throws AceException {

        TrlStore trlStore = new BasicTrlStore();

        CBORObject diffSetArray = diffSetObj.getLatestDiffEntries(3);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, diffSetArray);
        trlStore.processDiffQuery(map);

        Set<String> localTrl = trlStore.getLocalTrl();

        Set<String> expectedTrl = new HashSet<String>(){{add("th4");add("th5");add("th6");}};

        assert(localTrl.containsAll(expectedTrl));
        assert(expectedTrl.containsAll(localTrl));
    }

    @Test
    public void testFullQueryAndThenDiffQuery() throws AceException {

        TrlStore trlStore = new BasicTrlStore();
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.FULL_SET, fullSetArray);
        trlStore.processFullQuery(map);

        CBORObject diffSetArray = diffSetObj.getLatestDiffEntries(3);
        map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, diffSetArray);
        trlStore.processDiffQuery(map);

        Set<String> localTrl = trlStore.getLocalTrl();

        Set<String> expectedTrl = new HashSet<String>(){{add("th4");add("th5");add("th6");add("th8");}};

        assert(localTrl.containsAll(expectedTrl));
        assert(expectedTrl.containsAll(localTrl));

    }

}
