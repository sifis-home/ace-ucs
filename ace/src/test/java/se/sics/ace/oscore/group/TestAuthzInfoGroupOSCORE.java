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
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.TestConfig;
import se.sics.ace.as.Introspect;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;
import se.sics.ace.oscore.rs.AuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler4Tests;
import se.sics.ace.rs.TokenRepository;

/**
 * 
 * @author Ludwig Seitz and Marco Tiloca
 */
public class TestAuthzInfoGroupOSCORE {
    
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;

    private static AuthzInfoGroupOSCORE ai = null; // M.T.
    
    private static AuthzInfoGroupOSCORE ai2 = null; // M.T.
    // Created a separate authz-info endpoint using a dedicated introspection handler
    // for the audience "rs2" (OSCORE Group Manager). An actual fix would be defining
    // a new introspection handler, whose constructor takes as input a list of audience
    // identifiers, rather than a single RS identifier.
    
    private static Introspect i; 
    private static GroupOSCOREJoinPDP pdp = null; // M.T.
    
    private final static int groupIdPrefixSize = 4; // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
    
    private static Map<Integer, GroupInfo> activeGroups = new HashMap<>();
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() 
            throws SQLException, AceException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = key.PublicKey();

        
        OneKey sharedKey = new OneKey();
        sharedKey.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        sharedKey.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        sharedKey.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client1", profiles, null, null, keyTypes, null, 
                publicKey);
        db.addClient("client2", profiles, null, null, keyTypes, sharedKey,
                publicKey);

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
        // Adding the join resource, as one scope for each different combinations of
        // roles admitted in the OSCORE Group, with zeroed-epoch Group ID "feedca570000".
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put("feedca570000", actions2);
        myScopes.put("feedca570000_requester", myResource3);
        myScopes.put("feedca570000_responder", myResource3);
        myScopes.put("feedca570000_monitor", myResource3);
        myScopes.put("feedca570000_requester_responder", myResource3);
        myScopes.put("feedca570000_requester_monitor", myResource3);
        
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
    	
    	GroupInfo myGroup = new GroupInfo(masterSecret,
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
    	// If the groupIdPrefix is 4 bytes in size, the map key can be a negative integer, but it is not a problem
    	activeGroups.put(Integer.valueOf(GroupInfo.bytesToInt(groupIdPrefix)), myGroup);
       
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token files
        new File(tokenFile).delete();
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        pdp = new GroupOSCOREJoinPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        pdp.addIntrospectAccess("rs2"); // M.T. Enabling introspection for the OSCORE Group Manager
        i = new Introspect(pdp, db, new KissTime(), key);
        
        // M.T.
        // Tests on this audience "rs1" are just the same as in TestAuthzInfo,
        // while using the endpoint AuthzInfoGroupOSCORE as for audience "rs2".
        ai = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), new IntrospectionHandler4Tests(i, "rs1", "TestAS"),
                valid, ctx, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the prefix size of OSCORE Group IDs
        ai.setGroupIdPrefixSize(groupIdPrefixSize);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(activeGroups);
        
        // M.T.
        // A separate authz-info endpoint is required for each audience, here "rs2",
        // due to the interface of the IntrospectionHandler4Tests taking exactly
        // one RS as second argument.
        ai2 = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), new IntrospectionHandler4Tests(i, "rs2", "TestAS"),
                valid, ctx, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the prefix size of OSCORE Group IDs
        ai2.setGroupIdPrefixSize(groupIdPrefixSize);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai2.setActiveGroups(activeGroups);
        
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        DBHelper.tearDownDB();
        pdp.close();
        i.close();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test inactive reference token submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testRefInactive() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        ReferenceToken token = new ReferenceToken(20);
        LocalMessage request = new LocalMessage(0, "client1", "rs1",
               CBORObject.FromObject(token.encode().EncodeToBytes()));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT with a scope claim that is overwritten by introspection
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testCwtIntrospect() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x01});
        //Make introspection succeed
        db.addToken(ctiStr, params);
        db.addCti2Client(ctiStr, "client1");
        
        //this overwrites the scope
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[]{0x00, 0x01});
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "client1", "rs1",
                token.encode(ctx));
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x01});
        String kidStr = new RawPublicKeyIdentity(
                publicKey.AsPublicKey()).getName();
        assert(1 == TokenRepository.getInstance().canAccess(
                kidStr, null, "co2", Constants.GET, null));

    }
    
    /**
     * Test CWT with invalid MAC submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.EXP, CBORObject.FromObject(1444064944));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));
        byte[] cti = {0x02};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject(
                "r+/s/light rwx+/a/led w+/dtls"));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128a, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);

        LocalMessage request = new LocalMessage(0, "client1", "rs1",
                cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test an invalid token format submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidTokenFormat() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        CBORObject token = CBORObject.False;
        LocalMessage request = new LocalMessage(0, "client1", "rs1",
                token);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test expired CWT submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testExpiredCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        byte[] cti = {0x03};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        String ctiStr = Base64.getEncoder().encodeToString(cti);
        
        //Make introspection succeed
        db.addToken(ctiStr, claims);
        db.addCti2Client(ctiStr, "client1");
        
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject(
                "r+/s/light rwx+/a/led w+/dtls")); 
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));        
        claims.put(Constants.EXP, CBORObject.FromObject(10000));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);
        
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test CWT with unrecognized issuer submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testIssuerNotRecognized() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x05}));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x05});
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x05}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("FalseAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "client1", "rs1",
                token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT without audience submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudience() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x06}));
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x06});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x06}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT with audience that does not match RS submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudienceMatch() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x07}));
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x07});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x07}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("blah"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
        assert(response.getMessageCode() == Message.FAIL_FORBIDDEN);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());   
    }  
    
    /**
     * Test CWT without scope submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoScope() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x08}), params);
        db.addCti2Client(ctiStr, "client1");

        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                token.encode(ctx));
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccess() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x09}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x09});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x09}), params);
        db.addCti2Client(ctiStr, "client1");  

        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), 
                new byte[]{0x09});
    }    
    
    /**
     * Test successful submission to AuthzInfo with an array of audiences
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testAudArray() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x11}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        CBORObject aud = CBORObject.NewArray();
        aud.Add(CBORObject.FromObject("rs1"));
        aud.Add(CBORObject.FromObject("foo"));
        aud.Add(CBORObject.FromObject("bar"));
        params.put(Constants.AUD, aud);
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x11});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x11}), params);
        db.addCti2Client(ctiStr, "client1");  

        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs1",
                token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), 
                new byte[]{0x11});
    }    

    // M.T.
    /**
     * Test successful submission to AuthzInfo, for
     * accessing an OSCORE group with a single role.
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccessGroupOSCORESingleRole() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
    	
        Map<Short, CBORObject> params = new HashMap<>();
        
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x12}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "rs2" acting as OSCORE Group Manager
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x12});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x12}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs2",
                token.encode(ctx));
              
        // Note the usage of the dedicated authz-info endpoint for this audience "rs2"
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), 
                new byte[]{0x12});
    }

    // M.T.
    /**
     * Test successful submission to AuthzInfo, for
     * accessing an OSCORE group with multiple roles.
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccessGroupOSCOREMultipleRoles() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
    	
        Map<Short, CBORObject> params = new HashMap<>();
        
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("monitor");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x13}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "rs2" acting as OSCORE Group Manager
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(
                kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x13});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x13}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, "clientA", "rs2",
                token.encode(ctx));
              
        // Note the usage of the dedicated authz-info endpoint for this audience "rs2"
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        System.out.println(response.toString());        
        assert(response.getMessageCode() == Message.CREATED);   
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), 
                new byte[]{0x13});
    }

}   

