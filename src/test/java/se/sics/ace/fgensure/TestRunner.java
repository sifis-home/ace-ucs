/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.fgensure;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.logging.Level;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import junit.framework.Test;
import se.sics.ace.as.TestDB;
import se.sics.ace.as.TestIntrospect;
import se.sics.ace.as.TestKissPDP;
import se.sics.ace.as.TestToken;
import se.sics.ace.coap.TestCoAPClient;
import se.sics.ace.coap.TestCoAPServer;
import se.sics.ace.coap.TestCoapsIntrospection;
import se.sics.ace.coap.dtlsProfile.TestAsInfo;
import se.sics.ace.coap.dtlsProfile.TestDtlspAuthzInfo;
import se.sics.ace.coap.dtlsProfile.TestDtlspClient;
import se.sics.ace.coap.dtlsProfile.TestDtlspPskStore;
import se.sics.ace.coap.dtlsProfile.TestDtlspServer;
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
               
        //DTLS profile tests: TestAsInfo TestDtlspAuthzInfo TestDtlspPskStore
        //DTLS profile tests that need TestDtlspServer to run: TestDtlspClient
        
        System.out.println("Running CWT tests");
        toggleSilence();
        Result r = JUnitCore.runClasses(CwtTest.class);
        toggleSilence();
        handleResult(r);
        
        System.out.println("Running AS tests");
        toggleSilence();
        r = JUnitCore.runClasses(TestDB.class, TestIntrospect.class, TestKissPDP.class, TestToken.class);
        toggleSilence();
        handleResult(r);
        
        System.out.println("Running RS tests");
        toggleSilence();
        r = JUnitCore.runClasses(TestAuthzInfo.class, TestRESTscope.class, TestTokenRepository.class);
        toggleSilence();
        handleResult(r);
        
        //Skipping TestBskStore to avoid trouble with Java UCE
        
        System.out.println("Running CoAP client tests");
        toggleSilence();
        RunTestServer as = new RunTestServer();
        as.run();
        r = JUnitCore.runClasses(TestCoAPClient.class);
        as.stop();
        toggleSilence();
        handleResult(r);
        
        System.out.println("Running CoAP introspection tests");
        toggleSilence();
        as = new RunTestServer();
        as.run();
        r = JUnitCore.runClasses(TestCoapsIntrospection.class);
        as.stop();
        toggleSilence();
        handleResult(r);
        
        System.out.println("Running DTLS profile tests");
        toggleSilence();
        r = JUnitCore.runClasses(TestAsInfo.class, TestDtlspAuthzInfo.class, TestDtlspPskStore.class);
        toggleSilence();
        handleResult(r);
        
        System.out.println("Running DTLS profile client/server tests");
        toggleSilence();
        RunDtlsTestServer rs = new RunDtlsTestServer();
        rs.run();
        r = JUnitCore.runClasses(TestDtlspClient.class);
        rs.stop();
        toggleSilence();
        handleResult(r);
        
        System.exit(0);      
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
        
        public NullOutputStream(){ 
            //Does nothing
        }
    }
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         */
        public void stop() {
            TestCoAPServer.stop();
        }
        
        @Override
        public void run() {
            try {
                TestCoAPServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                TestCoAPServer.stop();
            }
        }
        
    }
    
    private static class RunDtlsTestServer implements Runnable {
        
        public RunDtlsTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         */
        public void stop() {
            TestDtlspServer.stop();
        }
        
        @Override
        public void run() {
            try {
                TestDtlspServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                TestDtlspServer.stop();
            }
        }
        
    }
}
