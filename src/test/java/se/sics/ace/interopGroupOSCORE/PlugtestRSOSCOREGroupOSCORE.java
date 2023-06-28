/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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
package se.sics.ace.interopGroupOSCORE;

import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.oscore.rs.OscoreAuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCOREGroupMembershipResource;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORERootGroupMembershipResource;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceActive;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceCreds;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceKdcCred;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceNodes;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceNum;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourcePolicies;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceStaleSids;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceVerifData;
import se.sics.ace.rs.AsRequestCreationHints;

/**
 * Server for testing the DTLSProfileDeliverer class. 
 * 
 * The Junit tests are in TestDtlspClientGroupOSCORE, 
 * which will automatically start this server.
 * 
 * @author Marco Tiloca
 *
 */
public class PlugtestRSOSCOREGroupOSCORE {

	// For old tests - PSK to encrypt the token (used for both audiences rs1 and rs2)
    private static byte[] key128_token = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 0x05,
    										    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    										    0x0d, 0x0e, 0x0f, 0x10};
    
    private final static String rootGroupMembershipResourcePath = "ace-group";
    
    // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
	private final static int groupIdPrefixSize = 4;
	
	// Initial part of the node name for monitors, since they do not have a Sender ID
	private final static String prefixMonitorNames = "M";
	
	// For non-monitor members, separator between the two components of the node name
	private final static String nodeNameSeparator = "-";
	
	// The maximum number of sets of stale Sender IDs for the group
	// This value must be strictly greater than 1
	private final static int maxStaleIdsSets = 3;
	
	// Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();

    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
	private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();

    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();

    // Uncomment to set curve X25519 for pairwise key derivation
	private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();
	
	static Map<String, GroupInfo> existingGroupInfo = new HashMap<>();

	private static int portNumberNoSec = 5690;
	
	// Sender ID 0x52 for an already present group member
	private static final byte[] idClient2 = new byte[] { (byte) 0x52 };
	
	// Sender ID 0x77 for an already present group member
	private static final byte[] idClient3 = new byte[] { (byte) 0x77 };
	
	// For the sake of testing, a particular Sender ID is used as known to be available.
    static byte[] senderId = new byte[] { (byte) 0x25 };

    private static OscoreAuthzInfoGroupOSCORE ai = null;

    private static CoapServer rs = null;

    private static CoapDeliverer dpd = null;

    private static Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();

    private static GroupOSCOREJoinValidator valid = null;

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

    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
    	
        //Set logging for slf4/blah
        BasicConfigurator.configure();
    	
        //Set java.util.logging
        Logger rootLogger = LogManager.getLogManager().getLogger("");
        rootLogger.setLevel(Level.FINEST);
        for (Handler h : rootLogger.getHandlers()) {
            h.setLevel(Level.FINEST);
        }
    	
    	new File(TestConfig.testFilePath + "tokens.json").delete();
		new File(TestConfig.testFilePath + "tokenhashes.json").delete();

    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 2);
    	Security.insertProviderAt(EdDSA, 1);

    	final String groupName = "feedca570000";
    	
        //Set up OSCORE Profile Token Repository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("helloWorld", actions);
        myScopes.put("r_helloWorld", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        // Adding the group-membership resource, with group name "feedca570000".
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResourcePath, actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.POST);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName, actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/creds", actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.GET);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred", actions3);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data", actions3);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/num", actions3);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/active", actions3);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/policies", actions3);
        actions3 = new HashSet<>();
        actions3.add(Constants.FETCH);
        myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids", actions3);
        myScopes.put(rootGroupMembershipResourcePath + "/" + groupName, myResource3);

        // Adding another group-membership resource, with group name "fBBBca570000".
        // There will NOT be a token enabling the access to this resource.
        Map<String, Set<Short>> myResource4 = new HashMap<>();
        Set<Short> actions4 = new HashSet<>();
        actions4.add(Constants.GET);
        actions4.add(Constants.POST);
        myResource4.put(rootGroupMembershipResourcePath + "/" + "fBBBca570000", actions4);
        myScopes.put(rootGroupMembershipResourcePath + "/", myResource4);
        
        String rsId = "rs1";
        
        Set<String> auds = new HashSet<>();
        auds.add("aud1"); // Simple test audience
        auds.add("aud2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResourcePath);
        
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("aud2"));
        
        // Include the root group-membership resource for Group OSCORE.
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath));
        
        // For each OSCORE group, include the associated group-membership resource and its sub-resources
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/creds"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/num"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/active"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/policies"));
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids"));
        
        
    	String tokenFile = TestConfig.testFilePath + "tokens.json";
		String tokenHashesFile = TestConfig.testFilePath + "tokenhashes.json";
		//Delete lingering old files
    	new File(tokenFile).delete();
		new File(tokenHashesFile).delete();

        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128_token, coseP.getAlg().AsCBOR());

        // Set up the inner Authz-Info library
        ai = new OscoreAuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), new KissTime(),
				null, rsId, valid, ctx, tokenFile, tokenHashesFile, valid, false, 86400000L);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(existingGroupInfo);
      
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
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
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
      
  	    AsRequestCreationHints asi = new AsRequestCreationHints("coaps://blah/authz-info/", null, false, false);
  	    Resource hello = new HelloWorldResource();
  	    Resource temp = new TempResource();
  	    Resource authzInfo = new CoapAuthzInfo(ai);
  	    
  	    Resource groupOSCORERootGroupMembership = new GroupOSCORERootGroupMembershipResource(rootGroupMembershipResourcePath,
				     																		 existingGroupInfo);

        Resource groupMembershipResource = new GroupOSCOREGroupMembershipResource(groupName,
																				  existingGroupInfo,
																				  rootGroupMembershipResourcePath,
																				  myScopes,
																				  valid);
		// Add the /creds sub-resource
		Resource credsSubResource = new GroupOSCORESubResourceCreds("creds", existingGroupInfo);
		groupMembershipResource.add(credsSubResource);

		// Add the /kdc-cred sub-resource
		Resource kdcCredSubResource = new GroupOSCORESubResourceKdcCred("kdc-cred", existingGroupInfo);
		groupMembershipResource.add(kdcCredSubResource);

		// Add the /verif-data sub-resource
		Resource verifDataSubResource = new GroupOSCORESubResourceVerifData("verif-data", existingGroupInfo);
		groupMembershipResource.add(verifDataSubResource);

		// Add the /num sub-resource
		Resource numSubResource = new GroupOSCORESubResourceNum("num", existingGroupInfo);
		groupMembershipResource.add(numSubResource);

		// Add the /active sub-resource
		Resource activeSubResource = new GroupOSCORESubResourceActive("active", existingGroupInfo);
		groupMembershipResource.add(activeSubResource);

		// Add the /policies sub-resource
		Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies", existingGroupInfo);
		groupMembershipResource.add(policiesSubResource);

		// Add the /stale-sids sub-resource
		Resource staleSidsSubResource = new GroupOSCORESubResourceStaleSids("stale-sids", existingGroupInfo);
		groupMembershipResource.add(staleSidsSubResource);

		// Add the /nodes sub-resource, as root to actually accessible per-node sub-resources
		Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes");
		groupMembershipResource.add(nodesSubResource);
  	    

        // Create the OSCORE Group(s)
        if (!OSCOREGroupCreation(groupName, signKeyCurve, ecdhKeyCurve))
        	return;

  	    rs = new CoapServer();
  	    rs.add(hello);
  	    rs.add(temp);
  	    rs.add(groupOSCORERootGroupMembership);
  	    groupOSCORERootGroupMembership.add(groupMembershipResource);
  	    rs.add(authzInfo);
      
  	    // Setup the OSCORE server
  	    CoapEndpoint cep = new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(portNumberNoSec)
                .setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance())
                .build();
  	    rs.addEndpoint(cep);

  	    dpd = new CoapDeliverer(rs.getRoot(), null, asi, cep);
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
    public static void stop() throws IOException, AceException {
        rs.stop();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
		new File(TestConfig.testFilePath + "tokenhashes.json").delete();
    }

    private static boolean OSCOREGroupCreation(String groupName, int signKeyCurve, int ecdhKeyCurve)
			throws CoseException, Exception
	{
		// Create the OSCORE group
	    final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
	            					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
	            					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
	            					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };




	    final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
	            					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

	    final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
	    final int credFmt = Constants.COSE_HEADER_PARAM_CCS;

	    AlgorithmID gpEncAlg = null;
	    AlgorithmID signAlg = null;
	    CBORObject signAlgCapabilities = null;
	    CBORObject signKeyCapabilities = null;
	    CBORObject signParams = null;

	    AlgorithmID alg = null;
	    AlgorithmID ecdhAlg = null;
	    CBORObject ecdhAlgCapabilities = null;
	    CBORObject ecdhKeyCapabilities = null;
	    CBORObject ecdhParams = null;

		// Generate a pair of asymmetric keys and print them in base 64 (whole version, then public only)
	    /*
	    OneKey testKey = null;

			if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
				testKey = OneKey.generateKey(AlgorithmID.ECDSA_256);

		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
			testKey = OneKey.generateKey(AlgorithmID.EDDSA);

		byte[] testKeyBytes = testKey.EncodeToBytes();
		String testKeyBytesBase64 = Base64.getEncoder().encodeToString(testKeyBytes);
		System.out.println(testKeyBytesBase64);

		OneKey testPublicKey = testKey.PublicKey();
		byte[] testPublicKeyBytes = testPublicKey.EncodeToBytes();
		String testPublicKeyBytesBase64 = Base64.getEncoder().encodeToString(testPublicKeyBytes);
		System.out.println(testPublicKeyBytesBase64);
		*/

	    if (signKeyCurve == 0 && ecdhKeyCurve == 0) {
	    	System.out.println("Both the signature key curve and the ECDH key curve are unspecified");
	    	return false;
	    }
	    int mode = GroupcommParameters.GROUP_OSCORE_GROUP_PAIRWISE_MODE;
	    if (signKeyCurve != 0 && ecdhKeyCurve == 0)
	    	mode = GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY;
	    else if (signKeyCurve == 0 && ecdhKeyCurve != 0)
	    	mode = GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY;


	    if (mode != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
	    	gpEncAlg = AlgorithmID.AES_CCM_16_64_128;
	        signAlgCapabilities = CBORObject.NewArray();
	        signKeyCapabilities = CBORObject.NewArray();
	        signParams = CBORObject.NewArray();

	        // ECDSA_256
	        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        	signAlg = AlgorithmID.ECDSA_256;
	        	signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
	        	signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
	        	signKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
	        }
	        
	        // EDDSA (Ed25519)
	        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        	signAlg = AlgorithmID.EDDSA;
	        	signAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
	        	signKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
	        	signKeyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
	        }
	        
	    	signParams.Add(signAlgCapabilities);
	    	signParams.Add(signKeyCapabilities);
	    }

	    if (mode != GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY) {
	        alg = AlgorithmID.AES_CCM_16_64_128;
	    	ecdhAlg = AlgorithmID.ECDH_SS_HKDF_256;
	        ecdhAlgCapabilities = CBORObject.NewArray();
	        ecdhKeyCapabilities = CBORObject.NewArray();
	        ecdhParams = CBORObject.NewArray();
	        
	        // ECDSA_256
	        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        	ecdhAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
	        	ecdhKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
	        	ecdhKeyCapabilities.Add(KeyKeys.EC2_P256);    // Curve
	        }
	        
	        // EDDSA (Ed25519)
	        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
	        	ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
	        	ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
	        	ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519);  // Curve
	        }
	        
	    	ecdhParams.Add(ecdhAlgCapabilities);
	    	ecdhParams.Add(ecdhKeyCapabilities);

	    }


	    if (existingGroupInfo.containsKey(groupName)) {

	    	System.out.println("The OSCORE group " + groupName + " already exists.");
	    	return false;

	    }

	    // Prefix (4 byte) and Epoch (2 bytes)
	    // All Group IDs have the same prefix size, but can have different Epoch sizes
	    // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c
		final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
		byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes


		// Set the asymmetric key pair and public key of the Group Manager

		// Serialization of the COSE Key including both private and public part
		byte[] gmKeyPairBytes = null;

		// The asymmetric key pair and public key of the Group Manager (ECDSA_256)
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			gmKeyPairBytes = Utils.hexToBytes("a60102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b2358204a7b844a4c97ef91ed232aa564c9d5d373f2099647f9e9bd3fe6417a0d0f91ad");
		}

		// The asymmetric key pair and public key of the Group Manager (EDDSA - Ed25519)
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			gmKeyPairBytes = Utils.hexToBytes("a5010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb");
		}

		OneKey gmKeyPair = null;
		gmKeyPair = new OneKey(CBORObject.DecodeFromBytes(gmKeyPairBytes));


		// Serialization of the authentication credential, according to the format used in the group
		byte[] gmAuthCred = null;

		/*
		// Build the authentication credential according to the format used in the group
		// Note: most likely, the result will NOT follow the required deterministic
		//       encoding in byte lexicographic order, and it has to be adjusted offline
		switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	String subjectName = "";
	            gmAuthCred = Util.oneKeyToCCS(gmKeyPair, subjectName);
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	            break;
		}
		*/

		switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        		gmAuthCred = Utils.hexToBytes("A2026008A101A50102032620012158202236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540225820770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B");
	        	}
	        	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        		gmAuthCred = Utils.hexToBytes("A2026008A101A4010103272006215820C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3");
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
		}


		GroupInfo myGroupInfo = new GroupInfo(groupName,
										      masterSecret,
										      masterSalt,
										      groupIdPrefixSize,
										      groupIdPrefix,
										      groupIdEpoch.length,
										      Util.bytesToInt(groupIdEpoch),
										      prefixMonitorNames,
										      nodeNameSeparator,
										      hkdf,
										      credFmt,
										      mode,
										      gpEncAlg,
										      signAlg,
										      signParams,
										      alg,
										      ecdhAlg,
										      ecdhParams,
										      null,
										      gmKeyPair,
										      gmAuthCred,
										      maxStaleIdsSets);

		myGroupInfo.setStatus(true);

		byte[] mySid;
		String myName;
		String mySubject;


		// Generate a pair of ECDSA_256 keys and print them in base 64 (whole version, then public only)
		/*
		OneKey testKey = OneKey.generateKey(AlgorithmID.ECDSA_256);

		byte[] testKeyBytes = testKey.EncodeToBytes();
		String testKeyBytesBase64 = Base64.getEncoder().encodeToString(testKeyBytes);
		System.out.println(testKeyBytesBase64);

		OneKey testPublicKey = testKey.PublicKey();
		byte[] testPublicKeyBytes = testPublicKey.EncodeToBytes();
		String testPublicKeyBytesBase64 = Base64.getEncoder().encodeToString(testPublicKeyBytes);
		System.out.println(testPublicKeyBytesBase64);
		*/

		// Add a group member with Sender ID 0x52
		mySid = new byte[] { (byte) 0x52 };

		if (!myGroupInfo.allocateSenderId(mySid))
			return false;
		myName = myGroupInfo.allocateNodeName(mySid);
		mySubject = "clientX";

		int roles = 0;
		roles = Util.addGroupOSCORERole(roles, GroupcommParameters.GROUP_OSCORE_REQUESTER);

		if (!myGroupInfo.addGroupMember(mySid, myName, roles, mySubject))
			return false;


		// Set the public key of the group member with Sender ID 0x52

		// The serialization of the COSE Key, including only the public part
		byte[] coseKeyPub1 = null;
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			coseKeyPub1 = Utils.hexToBytes("a501020326200121582035f3656092e1269aaaee6262cd1c0d9d38ed78820803305bc8ea41702a50b3af2258205d31247c2959e7b7d3f62f79622a7082ff01325fc9549e61bb878c2264df4c4f");
		}
		// Store the authentication credential of the group member with Sender ID 0x52
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			coseKeyPub1 = Utils.hexToBytes("a401010327200621582077ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b");
		}

		// Serialization of the authentication credential, according to the format used in the group
		byte[] authCred1 = null;

		/*
		// Build the authentication credential according to the format used in the group
		// Note: most likely, the result will NOT follow the required deterministic
		//       encoding in byte lexicographic order, and it has to be adjusted offline
		OneKey coseKeyPub1OneKey = null;
		coseKeyPub1OneKey = new OneKey(CBORObject.DecodeFromBytes(coseKeyPub1));
		switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	String subjectName = "";
	        	authCred1 = Util.oneKeyToCCS(coseKeyPub1OneKey, subjectName);
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	        	authCred1 = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	authCred1 = null;
	            break;
		}
		*/

		switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        		authCred1 = Utils.hexToBytes("A2026008A101A501020326200121582035F3656092E1269AAAEE6262CD1C0D9D38ED78820803305BC8EA41702A50B3AF2258205D31247C2959E7B7D3F62F79622A7082FF01325FC9549E61BB878C2264DF4C4F");
	        	}
	        	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        		authCred1 = Utils.hexToBytes("A2026008A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	        	authCred1 = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	authCred1 = null;
	            break;
		}

		// Store the authentication credential of the group member with Sender ID 0x52
		myGroupInfo.storeAuthCred(mySid, CBORObject.FromObject(authCred1));


		// Add a group member with Sender ID 0x77
		mySid = new byte[] { (byte) 0x77 };
		if (!myGroupInfo.allocateSenderId(mySid))
			return false;
		myName = myGroupInfo.allocateNodeName(mySid);
		mySubject = "clientY";

		roles = 0;
		roles = Util.addGroupOSCORERole(roles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
		roles = Util.addGroupOSCORERole(roles, GroupcommParameters.GROUP_OSCORE_RESPONDER);

		if (!myGroupInfo.addGroupMember(mySid, myName, roles, mySubject))
			return false;

		// Set the public key of the group member with Sender ID 0x77

		// The serialization of the COSE Key, including only the public part
		byte[] coseKeyPub2 = null;
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			coseKeyPub2 = Utils.hexToBytes("a50102032620012158209dfa6d63fd1515761460b7b02d54f8d7345819d2e5576c160d3148cc7886d5f122582076c81a0c1a872f1730c10317ab4f3616238fb23a08719e8b982b2d9321a2ef7d");
		}
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			coseKeyPub2 = Utils.hexToBytes("a4010103272006215820105b8c6a8c88019bf0c354592934130baa8007399cc2ac3be845884613d5ba2e");
		}


		// Serialization of the authentication credential, according to the format used in the group
		byte[] authCred2 = null;

		/*
		// Build the authentication credential according to the format used in the group
		// Note: most likely, the result will NOT follow the required deterministic
		//       encoding in byte lexicographic order, and it has to be adjusted offline
		OneKey coseKeyPub2OneKey = null;
		coseKeyPub2OneKey = new OneKey(CBORObject.DecodeFromBytes(coseKeyPub2));
		switch (credFmt) {
	    case Constants.COSE_HEADER_PARAM_CCS:
	        // A CCS including the public key
	    	String subjectName = "";
	    	authCred2 = Util.oneKeyToCCS(coseKeyPub2OneKey, subjectName);
	        break;
	    case Constants.COSE_HEADER_PARAM_CWT:
	        // A CWT including the public key
	        // TODO
	    	authCred2 = null;
	        break;
	    case Constants.COSE_HEADER_PARAM_X5CHAIN:
	        // A certificate including the public key
	        // TODO
	    	authCred2 = null;
	        break;
		}
		*/

		switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        		authCred2 = Utils.hexToBytes("A2026008A101A50102032620012158209DFA6D63FD1515761460B7B02D54F8D7345819D2E5576C160D3148CC7886D5F122582076C81A0C1A872F1730C10317AB4F3616238FB23A08719E8B982B2D9321A2EF7D");
	        	}
	        	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        		authCred2 = Utils.hexToBytes("A2026008A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	        	authCred2 = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	authCred2 = null;
	            break;
		}

		// Store the authentication credential of the group member with Sender ID 0x77
		myGroupInfo.storeAuthCred(mySid, CBORObject.FromObject(authCred2));


		// Store the information on this OSCORE group
		existingGroupInfo.put(groupName, myGroupInfo);

		return true;

	}

}
