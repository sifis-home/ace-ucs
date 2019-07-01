package se.sics.ace.coap.oscoreProfile;

import java.io.File;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AsRequestCreationHints;

/**
 * A RS for testing the OSCORE profile of ACE (https://datatracker.ietf.org/doc/draft-ietf-ace-oscore-profile)
 * @author Ludwig Seitz
 *
 */
public class OscoreRSTestServer {

    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {
            
            // set resource identifier
            super("helloWorld");
            
            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("Hello World!");
        }
    }
    
    /**
     * Definition of the Temp Resource
     */
    public static class TempResource extends CoapResource {
        
        /**
         * Constructor
         */
        public TempResource() {
            
            // set resource identifier
            super("temp");
            
            // set display name
            getAttributes().setTitle("Temp Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("19.0 C");
        }
    }
    
    private static OscoreAuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;  
    
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
      //Set up DTLSProfileTokenRepository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_helloWorld", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);

        byte[] key128a 
            = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      
               
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());

        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token files
        new File(tokenFile).delete();
        
      //Set up the inner Authz-Info library
      ai = new OscoreAuthzInfo(Collections.singletonList("TestAS"), 
                new KissTime(), null, valid, ctx,
                tokenFile, valid, false);
      
      //Add a test token to authz-info
      byte[] key128
          = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      Map<Short, CBORObject> params = new HashMap<>(); 
      params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
      params.put(Constants.AUD, CBORObject.FromObject("rs1"));
      params.put(Constants.CTI, CBORObject.FromObject(
              "token1".getBytes(Constants.charset)));
      params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

      OneKey key = new OneKey();
      key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
      
      byte[] kid  = new byte[] {0x01, 0x02, 0x03};
      CBORObject kidC = CBORObject.FromObject(kid);
      key.add(KeyKeys.KeyId, kidC);
      key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

      CBORObject cnf = CBORObject.NewMap();
      cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
      params.put(Constants.CNF, cnf);
      CWT token = new CWT(params);
      CBORObject payload = CBORObject.NewMap();
      payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx));
      byte[] n1 = new byte[8];
      new SecureRandom().nextBytes(n1);
      payload.Add(Constants.CNONCE, n1);
      
      ai.processMessage(new LocalMessage(0, null, null, token.encode(ctx)));

      AsRequestCreationHints archm 
          = new AsRequestCreationHints(
                  "coaps://blah/authz-info/", null, false, false);
      Resource hello = new HelloWorldResource();
      Resource temp = new TempResource();
      Resource authzInfo = new CoapAuthzInfo(ai);
      
      OSCoreCoapStackFactory.useAsDefault();
      rs = new CoapServer();
      rs.add(hello);
      rs.add(temp);
      rs.add(authzInfo);
      

      dpd = new CoapDeliverer(rs.getRoot(), null, archm); 

      rs.setMessageDeliverer(dpd);
      rs.start();
      System.out.println("Server starting");
      
      
      
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws AceException {
        rs.stop();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }


}
