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
import se.sics.ace.coap.rs.CoapAuthzInfoGroupOSCORE; // M.T.
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.GroupOSCOREJoinValidator; // M.T.
import se.sics.ace.rs.AuthzInfoGroupOSCORE; // M.T.
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
    private static TokenRepository tr;
    private static CwtCryptoCtx ctx;
    private static AuthzInfoGroupOSCORE ai; // M.T.
    private static AuthzInfoGroupOSCORE ai2; // M.T.
    private static CoapAuthzInfoGroupOSCORE dai; // M.T.
    private static CoapAuthzInfoGroupOSCORE dai2; // M.T.
    private static CBORObject payload;
    private static CBORObject payload2; // M.T.
    private static CBORObject payload3; // M.T.
    
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
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        //Set up the inner Authz-Info library
        ai = new AuthzInfoGroupOSCORE(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                null,
                valid, ctx);
        
        //Set up the DTLS authz-info resource
        dai = new CoapAuthzInfoGroupOSCORE(ai);
        
        // M.T.
        // Tests on the audience "rs1" are just the same as in TestAuthzInfo,
        // while using the endpoint AuthzInfoGroupOSCORE as for audience "rs2".
        ai2 = new AuthzInfoGroupOSCORE(tr, Collections.singletonList("TestAS"), 
                new KissTime(), 
                null,
                valid, ctx);
        
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
        String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
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
    	String role2 = new String("listener");
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byteStringScope = cborArrayScope.EncodeToBytes();
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
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
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
        Assert.assertArrayEquals(key128,
                ai.getKey(kid).get(KeyKeys.Octet_K).GetByteString());
               
      
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kid, kid, "temp", Constants.GET, null));
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
        Assert.assertArrayEquals(key128,
                ai2.getKey(kid).get(KeyKeys.Octet_K).GetByteString());
               
      
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kid, kid, "feedca570000", Constants.POST, null));
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
        Assert.assertArrayEquals(key128,
                ai2.getKey(kid).get(KeyKeys.Octet_K).GetByteString());
               
      
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                tr.canAccess(kid, kid, "feedca570000", Constants.POST, null));
    }
    
    /**
     * Deletes the test file after the tests
     */
    @AfterClass
    public static void tearDown() {
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
}
