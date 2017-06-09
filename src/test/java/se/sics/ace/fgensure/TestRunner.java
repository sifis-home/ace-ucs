package se.sics.ace.fgensure;

import java.util.Collections;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import se.sics.ace.as.TestDB;
import se.sics.ace.as.TestKissPDP;
import se.sics.ace.as.TestToken;
import se.sics.ace.coap.TestCoAPClient;
import se.sics.ace.coap.TestCoapsIntrospection;
import se.sics.ace.cwt.CwtTest;
import se.sics.ace.rs.TestAuthzInfo;
import se.sics.ace.rs.TestRESTscope;
import se.sics.ace.rs.TestTokenRepository;

/**
 * This class lets users run the ACE library tests manually
 * 
 * @author Ludwig Seitz
 *
 */
public class TestRunner {

    /**
     * @param args first argument given is the number of the test
     */
    public static void main(String[] args) {
        // TODO Auto-generated method stub

        
        //CWT tests: CwtTest
        //AS tests: TestDB TestKissPDP TestToken
        //RS tests: TestAuthzInfo TestRESTscope TestTokenRepository
        //Coap tests: TestBksStore (fails if java UCE not installed)
        //Coap tests that need TestCoAPServer to run: TestCoAPClient TestCoapsIntrospection
        //DTLS profile tests: TestAsInfo TestDtlspAuthzInfo TestDtlspPskStore
        //DTLS profile tests that need TestDtlspServer to run: TestDtlspClient
        
        System.out.println("Running CWT tests");
        //FIXME: Set System.out to quiet
        Result r = JUnitCore.runClasses(CwtTest.class);
        handleResult(r);
        System.out.println("Running AS tests");
        r = JUnitCore.runClasses(TestDB.class, TestKissPDP.class, TestToken.class);
        handleResult(r);
        System.out.println("Running RS tests");
        r = JUnitCore.runClasses(TestAuthzInfo.class, TestRESTscope.class, TestTokenRepository.class);
        handleResult(r);
        //Skipping TestBskStore to avoid trouble with Java UCE
        System.out.println("Running CoAP client tests");
        //FIXME: Start server on another thread
        r = JUnitCore.runClasses(TestCoAPClient.class);
        //FIXME: Stop server
        handleResult(r);
        System.out.println("Running CoAP introspection tests");
        //FIXME: Start server on another thread
        r = JUnitCore.runClasses(TestCoapsIntrospection.class);
        //FIXME: Stop server
        handleResult(r);
        
        

    }

    private static void handleResult(Result r) {
        if (r.getFailureCount() == 0) {
            System.out.println("[SUCCESS]");
        } else {
            for (Failure f : r.getFailures()) {
                System.out.println("[FAIL] " + f);
            }
        }
    }
}
