package se.sics.ace.coap.oscoreProfile;

import java.util.Map;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;

/**
 * Test the DTLSProfileRequests class C->AS
 *  
 * NOTE: This will automatically start an AS in another thread 
 * 
 * @author Ludwig Seitz
 *
 */
public class TestOscorepClient2AS {
    

    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx ctx;
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            OscoreASTestServer.stop();
        }
        
        @Override
        public void run() {
            try {
                OscoreASTestServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    OscoreASTestServer.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    @BeforeClass
    public static void setUp() throws OSException {
        ctx = new OSCoreCtx(key128, true, null, 
                "clientA".getBytes(Constants.charset),
                "AS".getBytes(Constants.charset),
                null, null, null, null);
        srv = new RunTestServer();
        srv.run();
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    /**
     * Test successful retrieval of a token over OSCORE
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception {
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs1"),
                CBORObject.FromObject("r_temp rw_config foobar"), null);
        Response response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx);
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
    }

}

