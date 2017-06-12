package se.sics.ace.fgensure;

import java.io.OutputStream;
import java.io.PrintStream;

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

    private static PrintStream saveOut;
    private static PrintStream saveErr;
    
    /**
     * @param args first argument given is the number of the test
     */
    public static void main(String[] args) {
        saveOut = new PrintStream(new NullOutputStream());
        saveErr = new PrintStream(new NullOutputStream());
               
        //CWT tests: CwtTest
        //AS tests: TestDB TestKissPDP TestToken
        //RS tests: TestAuthzInfo TestRESTscope TestTokenRepository
        //Coap tests: TestBksStore (fails if java UCE not installed)
        //Coap tests that need TestCoAPServer to run: TestCoAPClient TestCoapsIntrospection
        //DTLS profile tests: TestAsInfo TestDtlspAuthzInfo TestDtlspPskStore
        //DTLS profile tests that need TestDtlspServer to run: TestDtlspClient
        
        System.out.println("Running CWT tests");
        toggleSilence();
        Result r = JUnitCore.runClasses(CwtTest.class);
        toggleSilence();
        handleResult(r);
        System.out.println("Running AS tests");
        toggleSilence();
        r = JUnitCore.runClasses(TestDB.class, TestKissPDP.class, TestToken.class);
        toggleSilence();
        handleResult(r);
        System.out.println("Running RS tests");
        toggleSilence();
        r = JUnitCore.runClasses(TestAuthzInfo.class, TestRESTscope.class, TestTokenRepository.class);
        toggleSilence();
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
    
    /**
     * Toggle between NullOutputStream and default System.out
     */
    private static void toggleSilence() {
        PrintStream newO = saveOut;
        PrintStream newE = saveErr;
        saveOut = System.out;
        saveErr = System.err;
        System.setOut(newO);
        System.setErr(newE);
    }
    
    /**
     * A silent output stream
     * @author Ludwig Seitz
     *
     */
    private static class NullOutputStream extends OutputStream {
        
        @Override
        public void write(int b){
            return;
        }
        
        @Override
        public void write(byte[] b){
            return;
        }
        
        @Override
        public void write(byte[] b, int off, int len){
            return;
        }
        
        public NullOutputStream(){ //Does nothing
        }
    }

}
