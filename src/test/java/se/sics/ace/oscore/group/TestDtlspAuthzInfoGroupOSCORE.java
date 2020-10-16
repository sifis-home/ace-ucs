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
package se.sics.ace.oscore.group;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.AuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.CoapAuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfileAuthzInfo class.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspAuthzInfoGroupOSCORE {

    private static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static CwtCryptoCtx ctx;
    private static AuthzInfoGroupOSCORE ai; // M.T.
    private static AuthzInfoGroupOSCORE ai2; // M.T.
    private static CoapAuthzInfoGroupOSCORE dai; // M.T.
    private static CoapAuthzInfoGroupOSCORE dai2; // M.T.
    private static CBORObject payload;
    private static CBORObject payload2; // M.T.
    private static CBORObject payload3; // M.T.
    
    private final static int groupIdPrefixSize = 4; // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
    
    private final static String prefixMonitorNames = "M"; // Initial part of the node name for monitors, since they do not have a Sender ID
    
    private static Map<String, GroupInfo> activeGroups = new HashMap<>();
    
	private static final String rootGroupMembershipResource = "ace-group";
    
    /**
     * Set up the necessary objects.
     * 
     * @throws CoseException
     * @throws AceException
     * @throws IOException
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @BeforeClass
    public static void setUp() 
            throws CoseException, AceException, IOException, 
            IllegalStateException, InvalidCipherTextException {
        
        //Set up DTLSProfileTokenRepository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions.add(Constants.GET);
        actions.add(Constants.POST);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource.put("co2", actions2);
        myScopes.put("rw_co2", myResource2);
        
        // M.T.
        
        final String groupName = "feedca570000";
        
        // Adding the group-membership resource
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource3);
                
        // M.T.
        Set<String> auds = new HashSet<>();
        auds.add("rs1"); // Simple test audience
        auds.add("rs2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResource);
        
        // M.T.
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("rs2"));
        
        // M.T.
        // Include this resource as a group-membership resource for Group OSCORE.
        // The resource name is the name of the OSCORE group.
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        
        
        // Create the OSCORE group
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };

        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

        // Group OSCORE specific values for the AEAD algorithm and HKDF
        final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
        final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;

        // Group OSCORE specific values for the countersignature
        AlgorithmID csAlg = null;
        Map<CBORObject, CBORObject> csParamsMap = new HashMap<>();
        Map<CBORObject, CBORObject> csKeyParamsMap = new HashMap<>();
        
        // Uncomment to set ECDSA with curve P256 for countersignatures
        // int countersignKeyCurve = KeyKeys.EC2_P256.AsInt32();
        
        // Uncomment to set EDDSA with curve Ed25519 for countersignatures
        int countersignKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
        
        // ECDSA_256
        if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	csAlg = AlgorithmID.ECDSA_256;
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);        
        	csKeyParamsMap.put(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        }
        
        // EDDSA (Ed25519)
        if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	csAlg = AlgorithmID.EDDSA;
        	csParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        	csKeyParamsMap.put(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        	csKeyParamsMap.put(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
        }

        final CBORObject csParams = CBORObject.FromObject(csParamsMap);
        final CBORObject csKeyParams = CBORObject.FromObject(csKeyParamsMap);
        final CBORObject csKeyEnc = CBORObject.FromObject(Constants.COSE_KEY);
        
        final int senderIdSize = 1; // Up to 4 bytes

        // Prefix (4 byte) and Epoch (2 bytes) --- All Group IDs have the same prefix size, but can have different Epoch sizes
        // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c 
    	final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
    	byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes
    	
    	GroupInfo myGroup = new GroupInfo(groupName,
    									  masterSecret,
    			                          masterSalt,
    			                          groupIdPrefixSize,
    			                          groupIdPrefix,
    			                          groupIdEpoch.length,
    			                          GroupInfo.bytesToInt(groupIdEpoch),
    			                          prefixMonitorNames,
    			                          senderIdSize,
    			                          alg,
    			                          hkdf,
    			                          csAlg,
    			                          csParams,
    			                          csKeyParams,
    			                          csKeyEnc,
    			                          null);
        
    	// Add this OSCORE group to the set of active OSCORE groups
    	activeGroups.put(groupName, myGroup);
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering token files
        new File(tokenFile).delete();
        
        //Set up the inner Authz-Info library
        ai = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), null, valid, ctx, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(activeGroups);
        
        //Set up the DTLS authz-info resource
        dai = new CoapAuthzInfoGroupOSCORE(ai);
        
        // M.T.
        // Tests on the audience "rs1" are just the same as in TestAuthzInfo,
        // while using the endpoint AuthzInfoGroupOSCORE as for audience "rs2".
        ai2 = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), null, valid, ctx, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai2.setActiveGroups(activeGroups);
        
        // M.T.
        // A separate authz-info endpoint is required for each audience, here "rs2",
        // due to the interface of the IntrospectionHandler4Tests taking exactly
        // one RS as second argument.
        dai2 = new CoapAuthzInfoGroupOSCORE(ai2);
        
        //Set up a token to use
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[] {0x01, 0x02}); 
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        payload = token.encode(ctx);
        
        //Set up a token to use, for joining an OSCORE group with a single role
        Map<Short, CBORObject> params2 = new HashMap<>();
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params2.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params2.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key2 = new OneKey();
        key2.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid2 = CBORObject.FromObject(new byte[] {0x03, 0x04}); 
        key2.add(KeyKeys.KeyId, kid2);
        key2.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf2 = CBORObject.NewMap();
        cnf2.Add(Constants.COSE_KEY_CBOR, key2.AsCBOR());
        params2.put(Constants.CNF, cnf2);
        CWT token2 = new CWT(params2);
        payload2 = token2.encode(ctx);
        
        //Set up a token to use, for joining an OSCORE group with multiple roles
        Map<Short, CBORObject> params3 = new HashMap<>();
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// cborArrayEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params3.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params3.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params3.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x03}));
        params3.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key3 = new OneKey();
        key3.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid3 = CBORObject.FromObject(new byte[] {0x05, 0x06}); 
        key3.add(KeyKeys.KeyId, kid3);
        key3.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf3 = CBORObject.NewMap();
        cnf3.Add(Constants.COSE_KEY_CBOR, key3.AsCBOR());
        params3.put(Constants.CNF, cnf3);
        CWT token3 = new CWT(params3);
        payload3 = token3.encode(ctx);
        
    }
    
    /**
     * Test a POST to /authz-info
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtoken() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(),
                        CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x01});
        Exchange iex = new Exchange(req, Origin.REMOTE, null);
        iex.setRequest(req);   
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex, dai);      
        dai.handlePOST(ex);
      
        String kid = new String(new byte[]{0x01, 0x02}, Constants.charset);
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(
                        KeyKeys.Octet_K).GetByteString());
               
      
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(
                        kid, kid, "temp", Constants.GET, null));
    }
     
    // M.T.
    /**
     * Test a POST to /authz-info for accessing
     * an OSCORE group with a single role
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenGroupOSCORESingleRole() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload2.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(),
                        CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x02});
        Exchange iex = new Exchange(req, Origin.REMOTE, null);
        iex.setRequest(req);   
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex, dai2);      
        dai2.handlePOST(ex);
      
        String kid = new String(new byte[]{0x03, 0x04}, Constants.charset);
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(
                        KeyKeys.Octet_K).GetByteString());
               
        // Test that the token is there
        String groupName = "feedca570000";
        Assert.assertEquals(TokenRepository.OK, 
               TokenRepository.getInstance().canAccess(
                       kid, kid, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    // M.T.
    /**
     * Test a POST to /authz-info for accessing
     * an OSCORE group with multiple roles
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenGroupOSCOREMultipleRoles() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload3.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(),
                        CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x03});
        Exchange iex = new Exchange(req, Origin.REMOTE, null);
        iex.setRequest(req);   
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex, dai2);      
        dai2.handlePOST(ex);
      
        String kid = new String(new byte[]{0x05, 0x06}, Constants.charset);
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(
                        KeyKeys.Octet_K).GetByteString());
               
        //Test that the token is there
        String groupName = "feedca570000";
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(
                        kid, kid, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Deletes the test file after the tests
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException {
        ai.close();
        ai2.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
}
