/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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
package se.sics.ace.coap.dtlsProfile;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfoGroupOSCORE; // M.T.
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.dtlsProfile.DtlspPskStoreGroupOSCORE; // M.T.
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.GroupOSCOREJoinValidator; // M.T.
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.AuthzInfoGroupOSCORE; // M.T.
import se.sics.ace.rs.TokenRepository;

/**
 * Server for testing the DTLSProfileDeliverer class. 
 * 
 * The Junit tests are in TestDtlspClientGroupOSCORE, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspRSGroupOSCORE {


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
    
    // M.T.
    /**
     * Definition of the Group OSCORE Join Resource
     */
    public static class GroupOSCOREJoinResource extends CoapResource {
        
        /**
         * Constructor
         */
        public GroupOSCOREJoinResource(String resId) {
            
            // set resource identifier
            super(resId);
            
            // set display name
            getAttributes().setTitle("Group OSCORE Join Resource " + resId);
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            
        	Set<String> roles = new HashSet<>();
        	boolean providePublicKeys = false;
        	
        	byte[] requestPayload = exchange.getRequestPayload();
        	
        	CBORObject joinRequest = CBORObject.DecodeFromBytes(requestPayload);
        	
        	if (!joinRequest.getType().equals(CBORType.Map))
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The payload of the join request must be a CBOR Map");
        		
        	// More steps follow:
        	//
        	// Retrieve 'scope' from the map; check the GroupID against the name of the resource, just for consistency.
        	//
        	// Retrieve the role(s) to possibly reduce the set of material to provide to the joining node.
        	//
        	// Any other check is performed through the method canAccess() of the TokenRepository, which is
        	// in turn invoked by the deliverRequest() method of CoapDeliverer, upon getting the join request.
        	// The actual checks of legitimate access are performed by scopeMatchResource() and scopeMatch()
        	// of the GroupOSCOREJoinValidator used as Scope/Audience Validator.
        	
        	// Retrieve scope
        	CBORObject scope = joinRequest.get("scope");
        	
        	if (scope == null)
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Scope must be included for joining OSCORE groups");
        	
        	if (!scope.getType().equals(CBORType.ByteString)) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Scope must be wrapped in a binary string for joining OSCORE groups");
            }
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes((byte[])rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
            }
        	
        	if (cborScope.size() != 2) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
            }
        	
        	// Retrieve the Group ID of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		String scopeStr = scopeElement.AsString();
      	  		
      	  		// TODO: perform a consistency check between 'scopeStr' and this accessed join resource 
      	  	}
      	  	else {
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid scope format for joining OSCORE groups");
      	  	}
      	  	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		roles.add(scopeElement.AsString());
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The CBOR Array of roles must include at least two roles");
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString))
      	  				roles.add(scopeElement.get(i).AsString());
      	  			else {
      	  				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "The CBOR Array of roles must include at least two roles");
      	  			}
      	  		}
      	  	}
      	  	else {
      	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of roles");
      	  	}
        	
        	// Retrieve 'get_pub_keys'
        	// If present, this parameter must be an empty CBOR array
        	CBORObject getPubKeys = joinRequest.get("get_pub_keys");
        	if (getPubKeys != null) {
        		
        		if (!getPubKeys.getType().equals(CBORType.Array) && getPubKeys.size() != 0)
            		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "get_pub_keys must be an empty array");
        		
        		providePublicKeys = true;
        		
        		// TODO: Prepare the actual set of members' public key to be provided to the joining node
        		// Note: this considers the value of 'providePublicKeys' and the content of 
        		
        	}
        	
        	// Retrieve 'client_cred'
        	CBORObject clientCred = joinRequest.get("client_cred");
        	
        	if (clientCred == null) {
        	
        		// TODO: check if the Group Manager already owns this client's public key, otherwise reply with 4.00
        		
        	}
        	else {
        		
        		// TODO: store this client's public key 
        		// Note: this requires to understand if it's a COSE_Key, based on the signature algorithm used in the group
        		
        	}
        	
            // Respond to the request

            // TODO: complete the actual response content to include in the CBOR map
            
        	CBORObject joinResponse = CBORObject.NewMap();
        	
        	// Key Type Value assigned to the Group_OSCORE_Security_Context object.
        	// NOTE: '0' is a temporary value.
        	joinResponse.Add("kty", CBORObject.FromObject((int) 0));
        	
        	// This is the Group_OSCORE_Security_Context object.
        	// TODO: add inner parameters, by extending the OSCORE_Security_Context object.
        	joinResponse.Add("k", CBORObject.NewMap());
        	
        	// CBOR Value assigned to the coap_group_oscore profile.
        	// NOTE: '0' is a temporary value.
        	joinResponse.Add("profile", CBORObject.FromObject((int) 0));
        	
        	// Expiration time in seconds, after which the OSCORE Security Context
        	// derived from the 'k' parameter is not valid anymore.
        	joinResponse.Add("exp", CBORObject.FromObject((int) 1000000));
        	
        	// NOTE: this is currently skipping the inclusion of the optional
        	// parameters 'pub_keys', 'group_policies' and 'group_policies'.
        	
        	byte[] responsePayload = joinResponse.EncodeToBytes();
        	exchange.respond(ResponseCode.CREATED, responsePayload, MediaTypeRegistry.APPLICATION_CBOR);
        	
        }
    }
    
    private static TokenRepository tr = null;
    
    private static AuthzInfoGroupOSCORE ai = null; // M.T.
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;
    
    private static String rpk = "piJYILr/9Frrqur4bAz152+6hfzIG6v/dHMG+SK7XaC2JcEvI1ghAKryvKM6og3sNzRQk/nNqzeAfZsIGAYisZbRsPCE3s5BAyYBAiFYIIrXSWPfcBGeHZvB0La2Z0/nCciMirhJb8fv8HcOCyJzIAE=";
    
    
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
        
        // M.T.
        // Adding the join resource, as one scope for each different combinations of
        // roles admitted in the OSCORE Group, with zeroed-epoch Group ID "feedca570000".
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put("feedca570000", actions3);
        myScopes.put("feedca570000_requester", myResource3);
        myScopes.put("feedca570000_listener", myResource3);
        myScopes.put("feedca570000_purelistener", myResource3);
        myScopes.put("feedca570000_requester_listener", myResource3);
        myScopes.put("feedca570000_requester_purelistener", myResource3);
        
        // M.T.
        // Adding another join resource, as one scope for each different combinations of
        // roles admitted in the OSCORE Group, with zeroed-epoch Group ID "fBBBca570000".
        // There will NOT be a token enabling the access to this resource.
        Set<Short> actions4 = new HashSet<>();
        actions4.add(Constants.POST);
        Map<String, Set<Short>> myResource4 = new HashMap<>();
        myResource4.put("fBBBca570000", actions4);
        myScopes.put("fBBBca570000_requester", myResource4);
        myScopes.put("fBBBca570000_listener", myResource4);
        myScopes.put("fBBBca570000_purelistener", myResource4);
        myScopes.put("fBBBca570000_requester_listener", myResource4);
        myScopes.put("fBBBca570000_requester_purelistener", myResource4);
        
        // M.T.
        Set<String> auds = new HashSet<>();
        auds.add("rs1"); // Simple test audience
        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes);
        
        // M.T.
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("rs2"));
        
        // M.T.
        // Include this resource as a join resource for Group OSCORE.
        // The resource name is the zeroed-epoch Group ID of the OSCORE group.
        valid.setJoinResources(Collections.singleton("feedca570000"));
        
        createTR(valid);
        tr = TokenRepository.getInstance();
        
        byte[] key128a 
            = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      
        OneKey asymmetric = new OneKey(CBORObject.DecodeFromBytes(
                Base64.getDecoder().decode(rpk)));
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());

        
        //Set up the inner Authz-Info library
        ai = new AuthzInfoGroupOSCORE(tr, Collections.singletonList("TestAS"), 
        	 new KissTime(), 
             null,
             valid, ctx);
      
        // M.T.
        // The related test in TestDtlspClientGroupOSCORE still works with this server even with a single
        // AuthzInfoGroupOSCORE 'ai', but only because 'ai' is constructed with a null Introspection Handler.
        // 
        // If provided, a proper Introspection Handler would require to take care of multiple audiences,
        // rather than of a single RS as IntrospectionHandler4Tests does. This is already admitted in the
        // Java interface IntrospectionHandler.
      
        //Add a test token to authz-info
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
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
        ai.processMessage(new LocalMessage(0, null, null, token.encode(ctx)));

      
        // M.T.
        // Add a token to enable access to a join resource,
        // for joining an OSCORE group with a single role
        Map<Short, CBORObject> params2 = new HashMap<>();
        String gid = new String("feedca570000");
  	  	String role1 = new String("requester");
      
  	  	CBORObject cborArrayScope = CBORObject.NewArray();
  	  	cborArrayScope.Add(gid);
  	  	cborArrayScope.Add(role1);
  	  	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
  	  	params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
  	  	params2.put(Constants.AUD, CBORObject.FromObject("rs2"));
  	  	params2.put(Constants.CTI, CBORObject.FromObject(
                    "token2".getBytes(Constants.charset)));
  	  	params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));

  	  	OneKey key2 = new OneKey();
  	  	key2.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
      
  	  	byte[] kid2 = new byte[] {0x04, 0x05, 0x06};
  	  	CBORObject kidC2 = CBORObject.FromObject(kid2);
  	  	key2.add(KeyKeys.KeyId, kidC2);
  	  	key2.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

  	  	CBORObject cnf2 = CBORObject.NewMap();
  	   cnf2.Add(Constants.COSE_KEY_CBOR, key2.AsCBOR());
  	   params2.put(Constants.CNF, cnf2);
  	   CWT token2 = new CWT(params2);
  	   ai.processMessage(new LocalMessage(0, null, null, token2.encode(ctx)));
      
      
  	   // M.T.
  	   // Add a token to enable access to a join resource,
  	   // for joining an OSCORE group with multiple roles
  	   Map<Short, CBORObject> params3 = new HashMap<>();
  	   String role2 = new String("listener");
      
  	   cborArrayScope = CBORObject.NewArray();
  	   cborArrayScope.Add(gid);
  	   CBORObject cborArrayRoles = CBORObject.NewArray();
  	   cborArrayRoles.Add(role1);
  	   cborArrayRoles.Add(role2);
  	   cborArrayScope.Add(cborArrayRoles);
  	   byteStringScope = cborArrayScope.EncodeToBytes();
  	   params3.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
  	   params3.put(Constants.AUD, CBORObject.FromObject("rs2"));
  	   params3.put(Constants.CTI, CBORObject.FromObject(
                   "token3".getBytes(Constants.charset)));
  	   params3.put(Constants.ISS, CBORObject.FromObject("TestAS"));

  	   OneKey key3 = new OneKey();
  	   key3.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
      
  	   byte[] kid3 = new byte[] {0x07, 0x08, 0x09};
  	   CBORObject kidC3 = CBORObject.FromObject(kid3);
  	   key3.add(KeyKeys.KeyId, kidC3);
  	   key3.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

  	   CBORObject cnf3 = CBORObject.NewMap();
  	   cnf3.Add(Constants.COSE_KEY_CBOR, key3.AsCBOR());
  	   params3.put(Constants.CNF, cnf3);
  	   CWT token3 = new CWT(params3);
  	   ai.processMessage(new LocalMessage(0, null, null, token3.encode(ctx)));
      
      
  	   AsRequestCreationHints asi 
  	   = new AsRequestCreationHints("coaps://blah/authz-info/", null, false, false);
  	   Resource hello = new HelloWorldResource();
  	   Resource temp = new TempResource();
  	   Resource join = new GroupOSCOREJoinResource("feedca570000"); // M.T.
  	   Resource authzInfo = new CoapAuthzInfoGroupOSCORE(ai);
      
  	   rs = new CoapServer();
  	   rs.add(hello);
  	   rs.add(temp);
  	   rs.add(join); // M.T.
  	   rs.add(authzInfo);
      
  	   dpd = new CoapDeliverer(rs.getRoot(), tr, null, asi); 

      
  	   DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder()
              .setAddress(
                      new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
       config.setSupportedCipherSuites(new CipherSuite[]{
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
               CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
       config.setRpkTrustAll();
       DtlspPskStoreGroupOSCORE psk = new DtlspPskStoreGroupOSCORE(ai);
       config.setPskStore(psk);
       config.setIdentity(asymmetric.AsPrivateKey(), asymmetric.AsPublicKey());
       config.setClientAuthenticationRequired(true);
       DTLSConnector connector = new DTLSConnector(config.build());
       CoapEndpoint cep = new Builder().setConnector(connector)
               .setNetworkConfig(NetworkConfig.getStandard()).build();
       rs.addEndpoint(cep);
       //Add a CoAP (no 's') endpoint for authz-info
       CoapEndpoint aiep = new Builder().setInetSocketAddress(
               new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
       rs.addEndpoint(aiep);
       rs.setMessageDeliverer(dpd);
       rs.start();
       System.out.println("Server starting");
    }
    
    /**
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(GroupOSCOREJoinValidator valid) throws IOException {
        try {
            TokenRepository.create(valid, TestConfig.testFilePath 
                    + "tokens.json", null, new KissTime(), false, null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null, new KissTime(), false, null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws IOException, AceException {
        rs.stop();
        dpd.close();
        ai.close();
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }


}
