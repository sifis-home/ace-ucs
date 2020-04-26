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
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
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
import se.sics.ace.oscore.rs.DtlspPskStoreGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfilePskStoreGroupOSCORE class that implements fetching the access token from the
 * psk-identity in the DTLS handshake.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspPskStoreGroupOSCORE {

    private static DtlspPskStoreGroupOSCORE store = null;
   
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private static AuthzInfoGroupOSCORE ai;
    
    private final static int groupIdPrefixSize = 4; // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
    
    private static Map<String, GroupInfo> activeGroups = new HashMap<>();
    
	private static final String rootGroupMembershipResource = "group-oscore";
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() throws AceException, IOException {
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions);
        myScopes.put("r_co2", myResource2);
        
        // M.T.
    	final String groupName = "feedca570000";
        
        // Adding the group-membership resource, as one scope for each different combinations of
        // roles admitted in the OSCORE Group, with group name "feedca570000".
    	
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions2);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_requester", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_responder", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_monitor", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_requester_responder", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_responder_requester", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_requester_monitor", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_monitor_requester", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_requester_responder_monitor", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_requester_monitor_responder", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_responder_requester_monitor", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_responder_monitor_requester", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_monitor_requester_responder", myResource3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName + "_monitor_responder_requester", myResource3);
        
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
    			                          senderIdSize,
    			                          alg,
    			                          hkdf,
    			                          csAlg,
    			                          csParams,
    			                          csKeyParams,
    			                          csKeyEnc);
        
    	// Add this OSCORE group to the set of active groups

    	activeGroups.put(groupName, myGroup);
    	        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token files
        new File(tokenFile).delete();
        
        ai = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), null, valid, ctx,
                tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(activeGroups);
        
        store = new DtlspPskStoreGroupOSCORE(ai);
    }
    
    /**
     * Deletes the test file after the tests
     * 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException  {
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }  
    
    
    /**
     * Test with an invalid psk-identity (non-parseable)
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidPskId() throws Exception {
        SecretKey key = store.getKey(
                new PskPublicInformation("blah"));
        Assert.assertNull(key);
    }
    
    /**
     * Test with an invalid token in the psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidToken() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
        
        CBORObject tokenAsBytes = CBORObject.FromObject(
                tokenCB.EncodeToBytes());
        
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenAsBytes.EncodeToBytes()); 

        SecretKey psk = store.getKey(
                new PskPublicInformation(psk_identity));
        Assert.assertNull(psk);
    }

    /**
     * Test with an valid psk-identity
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskId() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }
     
    /**
     * Test with only a kid in the CBOR structure
     * 
     * @throws Exception
     */
    @Test
    public void testKid() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>(); 
        claims.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        claims.put(Constants.AUD, CBORObject.FromObject("rs1"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token3".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        TokenRepository.getInstance().addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with an valid psk-identity, when
     * joining an OSCORE group with a single role
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskIdGroupOSCORESingleRole() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	String role1 = new String("requester");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	cborArrayEntry.Add(role1);
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with an valid psk-identity, when
     * joining an OSCORE group with multiple roles
     * 
     * @throws Exception 
     */
    @Test
    public void testValidPskIdGroupOSCOREMultipleRoles() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayEntry.Add(cborArrayRoles);
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token5".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        CBORObject tokenCB = token.encode(ctx);
           
        String psk_identity = Base64.getEncoder().encodeToString(
                tokenCB.EncodeToBytes()); 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }

    // M.T.
    /**
     * Test with only a kid in the CBOR structure, when
     * joining an OSCORE group with a single role
     * 
     * @throws Exception
     */
    @Test
    public void testKidGroupOSCORESigleRole() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	String role1 = new String("requester");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	cborArrayEntry.Add(role1);
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        claims.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        claims.put(Constants.AUD, CBORObject.FromObject("rs2"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token6".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        TokenRepository.getInstance().addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }
    
    // M.T.
    /**
     * Test with only a kid in the CBOR structure, when
     * joining an OSCORE group with multiple roles
     * 
     * @throws Exception
     */
    @Test
    public void testKidGroupOSCOREMultipleRoles() throws Exception {
        Map<Short, CBORObject> claims = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("responder");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(groupName);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        claims.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        claims.put(Constants.AUD, CBORObject.FromObject("rs2"));
        claims.put(Constants.CTI, CBORObject.FromObject(
                "token7".getBytes(Constants.charset)));
        claims.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        claims.put(Constants.CNF, cnf);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        TokenRepository.getInstance().addToken(claims, ctx, null);
        String psk_identity = "ourKey"; 

        byte[] psk = store.getKey(
                new PskPublicInformation(psk_identity)).getEncoded();
        Assert.assertArrayEquals(key128 ,psk);
    }
    
}
