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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.TokenRepository;

/**
 * Tests for the TokenRepository class.
 * 
 * @author Marco Tiloca
 *
 */
public class TestTokenRepositoryGroupOSCORE {
    
    static OneKey asymmetricKey;
    static OneKey symmetricKey;
    static OneKey otherKey;
    static CwtCryptoCtx ctx;
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr; 
    private static CBORObject pskCnf;
    private static CBORObject rpkCnf;
    private static String ourKey = "ourKey";
    private static String rpk = "ni:///sha-256;-QCjSk6ojWX8-YaHwQMOkewLD7p89aFF2eh8shWDmKE";
    
	private static final String rootGroupMembershipResource = "ace-group";
	
	private static Map<String, Short> rolesToInt = new HashMap<>();
    
    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);

    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() 
            throws AceException, CoseException, IOException {

        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
               
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        CBORObject otherKeyData = CBORObject.NewMap();
        otherKeyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        otherKeyData.Add(KeyKeys.KeyId.AsCBOR(), "otherKey".getBytes(Constants.charset));
        otherKeyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(otherKeyData);
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
    	final String groupName = "feedca570000";
        
        // Adding the group-membership resource
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put(rootGroupMembershipResource + "/" + groupName, actions2);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource2);
        
        Set<String> auds = new HashSet<>();
        auds.add("aud1"); // Simple test audience
        auds.add("aud2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        
        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResource);
        
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("aud2"));
        
        // Include this resource as a group-membership resource for Group OSCORE.
        // The resource name is the name of the OSCORE group.
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        
    	rolesToInt.put("requester", GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	rolesToInt.put("responder", GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	rolesToInt.put("monitor", GroupcommParameters.GROUP_OSCORE_MONITOR);
        
        createTR(valid);
        tr = TokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());
        
        rpkCnf = CBORObject.NewMap();
        rpkCnf.Add(Constants.COSE_KEY_CBOR, asymmetricKey.PublicKey().AsCBOR()); 
       
    }
    
    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(GroupOSCOREJoinValidator valid) throws IOException {

    	String rsId = "rs1";
    	
        try {
            String tokenFile = TestConfig.testFilePath + "tokens.json";
            String tokenHashesFile = TestConfig.testFilePath + "tokenhashes.json";
            new File(tokenFile).delete();
            new File(tokenHashesFile).delete();
            TokenRepository.create(valid, tokenFile, tokenHashesFile, null, null,
                    0, new KissTime(), rsId);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                new File(TestConfig.testFilePath + "tokenhashes.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath
                        + "tokens.json", TestConfig.testFilePath
                        + "tokenhashes.json", null, null, 0, new KissTime(), rsId);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            } 
        }
    }
    
    /**
     * Deletes the test files after the tests
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException {
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
        new File(TestConfig.testFilePath + "tokenhashes.json").delete();
    }
    
    /**
     * Test add token without scope
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoScope() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Token has no scope"));
    }
    
    /**
     * Test add token without cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCti() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        params.remove(Constants.CTI); //Gets added by tr.addToken()
        CBORObject cticb = CBORObject.FromObject(buffer.putInt(0, params.hashCode()).array());
        String cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
        Assert.assertNotNull(tr.getPoP(cti));
    }
    
    /**
     * Test add token with invalid cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCti() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CTI, CBORObject.FromObject("token1"));
        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Cti has invalid format"));
    }
    
    /**
     * Test add token with duplicate cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenDuplicateCti() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Duplicate cti"));
    }
    
    /**
     * Test add token without cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCnf() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Token has no cnf"));
    }
    
    /**
     * Test add token with unknown kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenUnknownKid() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Token refers to unknown kid"));
    }
    
    /**
     * Test add token with invalid cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCnf() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blah", "blah".getBytes(Constants.charset));
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Malformed cnf claim in token"));
    }
    
    /**
     * Test add token with invalid Encrypt0
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenCnfInvalidEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(key128a);
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        
        params.put(Constants.CNF, cnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Error while decrypting a cnf claim"));
    }
    
    
    /**
     * Test add token with cnf without kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoKid() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("Malformed cnf claim in token"));
    }
    
    
    /**
     * Test add token with cnf with invalid kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidKid() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("blah"));
        params.put(Constants.CNF, cnf);

        AceException exception = assertThrows(AceException.class,
                							  () -> tr.addToken(null, params, ctx, null, -1));
        assertTrue(exception.getMessage().contains("cnf contains invalid kid"));
    }
    
    
    /**
     * Test add token with cnf containing COSE_Key
     *
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws CoseException 
     */
    @Test
    public void testTokenCnfCoseKey() 
            throws AceException, IntrospectionException, CoseException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));    
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        rpk = new RawPublicKeyIdentity(asymmetricKey.AsPublicKey()).getName();

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kid = Base64.getEncoder().encodeToString(rpk.getBytes());
        
        String kid2 = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));

        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kid, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.METHODNA, tr.canAccess(kid, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.FORBID, tr.canAccess(kid2, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kid2, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    /**
     * Test add token with cnf containing COSE_Key, to access a
     * group-membership resource for joining an OSCORE group with a single role
     *
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws CoseException 
     */
    @Test
    public void testTokenCnfCoseKeyGroupOSCORESingleRole() 
            throws AceException, IntrospectionException, CoseException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));        
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        rpk = new RawPublicKeyIdentity(asymmetricKey.AsPublicKey()).getName();
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test add token with cnf containing COSE_Key, to access a
     * group-membership resource for joining an OSCORE group with multiple roles
     *
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws CoseException 
     */
    @Test
    public void testTokenCnfCoseKeyGroupOSCOREMultipleRoles() 
            throws AceException, IntrospectionException, CoseException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        rpk = new RawPublicKeyIdentity(asymmetricKey.AsPublicKey()).getName();
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test add token with cnf containing known kid
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfKid() throws AceException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kidStr, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    /**
     * Test add token with cnf containing known kid, to access a
     * group-membership resource for joining an OSCORE group with a single role
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfKidGroupOSCORESingleRole() throws AceException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes(); 
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test add token with cnf containing known kid, to access a
     * group-membership resource for joining an OSCORE group with multiple roles
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfKidGroupOSCOREMultipleRoles() throws AceException, IntrospectionException {
    	Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException, 
            IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.FORBID,
                tr.canAccess(kidStr, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0, to access a
     * group-membership resource for joining an OSCORE group with a single role
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfEncrypt0GroupOSCORESingleRole() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException, 
            IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));

        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0, to access a
     * group-membership resource for joining an OSCORE group with multiple roles
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfEncrypt0GroupOSCOREMultipleRoles() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException, 
            IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK,
                tr.canAccess(kidStr, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess(rpk, null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));

        Assert.assertEquals(TokenRepository.UNAUTHZ,
                tr.canAccess("otherKey", null, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test pollTokens()
     *
     * @throws AceException 
     */
    @Test
    public void testPollToken() throws AceException {
        KissTime time = new KissTime();
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()-1000));
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        params.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000));
        tr.addToken(null, params, ctx, null, -1);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertNull(key1);
        Assert.assertNotNull(key2);
    }
    
    /**
     * Test getPoP()
     *
     * @throws AceException 
     */
    @Test
    public void testGetPoP() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertArrayEquals(symmetricKey.EncodeToBytes(), 
                key1.EncodeToBytes());
        Assert.assertArrayEquals(
                asymmetricKey.PublicKey().EncodeToBytes(),
                key2.EncodeToBytes());
    }
    
    
    /**
     * Remove lingering token entries
     * @throws AceException 
     */
    @After
    public void cleanup() throws AceException {
        tr.removeToken("dG9rZW4x");
        tr.removeToken("dG9rZW4y");
        tr.removeToken("Ba87cQ==");
    }
    
}
