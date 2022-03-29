package se.sics.ace.rs;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import se.sics.ace.*;
import se.sics.ace.as.DiffSet;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public class TestTrlManager {

    static OneKey asymmetricKey;
    static OneKey symmetricKey;
    static OneKey otherKey;
    static CwtCryptoCtx ctx;
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr;
    private static CBORObject pskCnf;
    private static CBORObject rpkCnf;
    private static String ourKey = "ourKey";
    private static String rpk = "ni:///sha-256;-QCjSk6ojWX8-YaHwQMOkewLD7p89aFF2eh8shWDmKE";

    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);


    @BeforeClass
    public static void setUp() throws AceException, CoseException, IOException {
        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);

        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);

        CBORObject otherKeyData = CBORObject.NewMap();
        otherKeyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        otherKeyData.Add(KeyKeys.KeyId.AsCBOR(), "otherKey".getBytes(Constants.charset));
        otherKeyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(otherKeyData);

        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);

        Map<String, Set<Short>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);

        KissValidator valid = new KissValidator(Collections.singleton("aud1"), myScopes);

        createTR(valid);
        tr = TokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());

        rpkCnf = CBORObject.NewMap();
        rpkCnf.Add(Constants.COSE_KEY_CBOR, asymmetricKey.PublicKey().AsCBOR());
    }


    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     *
     * @param valid
     * @throws IOException
     *
     */
    private static void createTR(KissValidator valid) throws IOException {
        String rsId = "rs1";

        try {
            String tokenFile = TestConfig.testFilePath + "tokens.json";
            String tokenHashesFile = TestConfig.testFilePath + "tokenhashes.json";
            new File(tokenFile).delete();
            new File(tokenHashesFile).delete();
            TokenRepository.create(valid, tokenFile, tokenHashesFile, null, null,
                    0, new KissTime(), rsId);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                new File(TestConfig.testFilePath + "tokenhashes.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath + "tokens.json",
                        TestConfig.testFilePath + "tokenhashes.json", null, null, 0, new KissTime(), rsId);
            } catch (AceException e2) {
                throw new RuntimeException(e2);
            }
        }
    }

    /**
     * Deletes the test file after the tests
     * @throws AceException
     */
    @AfterClass
    public static void tearDown() throws AceException {
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
        new File(TestConfig.testFilePath + "tokenhashes.json").delete();
    }

    private CBORObject addNewValidTokenAtRs(String tokenStr)
            throws AceException, InvalidCipherTextException, CoseException {

        TimeProvider time = new KissTime();

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject(tokenStr.getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        CBORObject exp = CBORObject.FromObject(time.getCurrentTime() + 10000000L);
        params.put(Constants.EXP, exp);

        // add a new token
        CWT cwt = new CWT(params);
        CBORObject token = cwt.encode(ctx, null, null);
        tr.addToken(token, params, ctx, null, -1);
        return token;
    }

    @Test
    public void TestTrlManagerDiff() throws Exception {

        CBORObject token1 = addNewValidTokenAtRs("token1");
        CBORObject token2 = addNewValidTokenAtRs("token2");
        CBORObject token3 = addNewValidTokenAtRs("token3");
        CBORObject token4 = addNewValidTokenAtRs("token4");

        // Suppose that:
        //   1) token1 is added to the TRL
        //   2) token2 is added to the TRL
        //   3) token1 is removed from the TRL
        //   4) token3 is added to the TRL
        //   5) token2 is removed from the TRL
        //
        // The TRL should now contain [token3].

        // A response to a full query request will contain this payload:
        String th3 = Util.computeTokenHash(CBORObject.FromObject(token3.EncodeToBytes()));
        CBORObject payload = CBORObject.NewArray();
        payload.Add(CBORObject.FromObject(th3.getBytes(Constants.charset)));

        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.FULL_SET, payload);

        TokenRepository.TrlManager trlMan = TokenRepository.getInstance().getTrlManager();
        trlMan.updateLocalTrl(map);

        assert(trlMan.getLocalTrl().size() == 1 || trlMan.getLocalTrl().contains(th3));

        // A response to a diff query request (with diff=3) will contain the payload:
//       [
//         [[th2], []   ],
//         [[]   , [th3]],
//         [[th1], []   ]
//       ]
        String th1 = Util.computeTokenHash(CBORObject.FromObject(token1.EncodeToBytes()));
        String th2 = Util.computeTokenHash(CBORObject.FromObject(token2.EncodeToBytes()));
        String th4 = Util.computeTokenHash(CBORObject.FromObject(token4.EncodeToBytes()));


        DiffSet Diff = new DiffSet(10);

        CBORObject added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject(th1.getBytes(Constants.charset)));
        Diff.pushDiffEntry(CBORObject.NewArray(), added);

        added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject(th2.getBytes(Constants.charset)));
        Diff.pushDiffEntry(CBORObject.NewArray(), added);

        CBORObject removed = CBORObject.NewArray();
        removed.Add(CBORObject.FromObject(th1.getBytes(Constants.charset)));
        Diff.pushDiffEntry(removed, CBORObject.NewArray());

        added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject(th3.getBytes(Constants.charset)));
        Diff.pushDiffEntry(CBORObject.NewArray(), added);

        removed = CBORObject.NewArray();
        removed.Add(CBORObject.FromObject(th2.getBytes(Constants.charset)));
        Diff.pushDiffEntry(removed, CBORObject.NewArray());

        payload = Diff.getLatestDiffEntries(3);

        map = CBORObject.NewMap();
        map.Add(Constants.DIFF_SET, payload);

        trlMan.updateLocalTrl(map);

        assert(trlMan.getLocalTrl().size() == 1 && trlMan.getLocalTrl().contains(th3));
        assert(trlMan.getValidTokensSet().size() == 3 && !trlMan.getValidTokensSet().contains(th3));
        assert(trlMan.getValidTokensSet().contains(th1));
        assert(trlMan.getValidTokensSet().contains(th2));
        assert(trlMan.getValidTokensSet().contains(th4));

        // TODO: (possible optimization)
        //       when the RS receives the diff query response, it could check
        //       whether among the removed tokens there is some token that is
        //       present in its set of valid tokens.
        //       If so, it should remove that token from the valid ones.

    }
}
