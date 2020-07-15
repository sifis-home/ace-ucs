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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.as.Token;
// import se.sics.ace.interopGroupOSCORE.TestCoAPClientGroupOSCORE.RunTestServer;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class PlugtestClientGroupOSCORE {
    
	/* START LIST OF KEYS */
	
	// For old tests
    private static byte[] key128_client_A = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_B = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_C = {0x41, 0x42, 0x43, 0x04, 0x05, 0x06, 0x07,
    		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_D = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    // For group joining tests
    private static byte[] key128_client_F = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};
    private static byte[] key128_client_G = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    
	// For old tests
    private static byte[] key128_rs1 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    // For group joining tests (rs2, rs3 and rs4 are Group Managers)
    private static byte[] key128_rs2 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};
    private static byte[] key128_rs3 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    private static byte[] key128_rs4 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x13};

	// For old tests - PSK to encrypt the token
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    // For group joining tests - PSK to encrypt the token (rs2, rs3 and rs4 are Group Managers)
    private static byte[] key128_token_rs2 = {(byte)0xb1, (byte)0xa2, (byte)0xa3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    private static byte[] key128_token_rs3 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x11};
    private static byte[] key128_token_rs4 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x12};
    
	// Public key of a RS (same for all the RSs)
    private static String rsX = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    private static String rsD = "00EA086573C683477D74EB7A0C63A6D031D5DEB10F3CC2876FDA6D3400CAA4E507";
    
    // Asymmetric keys of the AS
    private static String asX = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
    
	// Public key of a Client (client3)
    private static String cX = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    private static String cD = "00A43BAA7ED22FF2699BA62CA4999359B146F065A95C4E46017CD25EB89A94AD29";
    /* END LIST OF KEYS */
    
    // For old tests
    private static byte[] kid1 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBC};
    private static byte[] kid2 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBD};
    private static byte[] kid3 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBE};
    private static byte[] kid4 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBF};

    // For group joining tests
    private static byte[] kid6 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xAA};
    private static byte[] kid7 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xAB};
    
    //Needed to show token content
    private static CwtCryptoCtx ctx1 = null;
    private static CwtCryptoCtx ctx2 = null;
    private static CwtCryptoCtx ctx3 = null;
    private static CwtCryptoCtx ctx4 = null;
    
	// OLD SETUP
	/*
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    static RunTestServer srv = null;
    */
    
    private static String uri = "";
    private static int portNumberAS = 5689;
    private static int portNumberRSnosec = 5690;
    private static int portNumberRSsec = 5691;
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(PlugtestClientGroupOSCORE.class.getName() ); 
    
    /**
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args)
            throws Exception {
        
        if (args.length < 2) { 
            System.out.println("First argument should be the number of the"
                    + " test case, second the address of the other endpoint"
                    + "(AS/RS) without the path");
            // args[0] is the test case, 
            // args[1] is the address of the other endpoint
            return;
        }
        
        //Setup Client RPK
        CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(cX));
        CBORObject y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(cY));
        CBORObject d = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(cD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
        OneKey rpk = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(
                rpk.AsPublicKey()).getName();
        rpk.add(KeyKeys.KeyId, CBORObject.FromObject(
                keyId.getBytes(Constants.charset)));
        
        //Setup AS RPK
        CBORObject asRpkData = CBORObject.NewMap();
        asRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        asRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        asRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject as_x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(asX));
        CBORObject as_y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(asY));
        asRpkData.Add(KeyKeys.EC2_X.AsCBOR(), as_x);
        asRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), as_y);
        OneKey asRPK = new OneKey(asRpkData);  
        
        //Setup RS RPK (same for all RSs)
        CBORObject rsRpkData = CBORObject.NewMap();
        rsRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rsRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rsRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject rs_x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(rsX));
        CBORObject rs_y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(rsY));
        rsRpkData.Add(KeyKeys.EC2_X.AsCBOR(), rs_x);
        rsRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), rs_y);
        OneKey rsRPK = new OneKey(rsRpkData);
        
        //Setup PSKs
        CBORObject pskData = CBORObject.NewMap();
        pskData.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_A));
        pskData.Add(KeyKeys.KeyId.AsCBOR(), kid1);
        OneKey clientA_PSK = new OneKey(pskData);
        
        CBORObject pskData2 = CBORObject.NewMap();
        pskData2.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData2.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_B));
        pskData2.Add(KeyKeys.KeyId.AsCBOR(), kid2);
        OneKey clientB_PSK = new OneKey(pskData2);
       
        CBORObject pskData3 = CBORObject.NewMap();
        pskData3.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData3.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_C));
        pskData3.Add(KeyKeys.KeyId.AsCBOR(), kid3);
        OneKey clientC_PSK = new OneKey(pskData3);
        
        CBORObject pskData4 = CBORObject.NewMap();
        pskData4.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData4.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_D));
        pskData4.Add(KeyKeys.KeyId.AsCBOR(), kid4);
        OneKey clientD_PSK = new OneKey(pskData4);
        
        CBORObject pskData6 = CBORObject.NewMap();
        pskData6.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData6.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_F));
        pskData6.Add(KeyKeys.KeyId.AsCBOR(), kid6);
        OneKey clientF_PSK = new OneKey(pskData6);
        
        CBORObject pskData7 = CBORObject.NewMap();
        pskData7.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData7.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_G));
        pskData7.Add(KeyKeys.KeyId.AsCBOR(), kid7);
        OneKey clientG_PSK = new OneKey(pskData7);
        
        int testcase = Integer.parseInt(args[0]);
        uri = args[1]; 
        // add schema if not present
        if (!uri.contains("://")) {
            uri = "coaps://" + uri;
        }
        if (uri.endsWith("/")) {
            uri = uri.substring(-1);
        }
        uri = uri + ":";

        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        ctx1 = CwtCryptoCtx.encrypt0(key128_token_rs1, coseP.getAlg().AsCBOR());
        ctx2 = CwtCryptoCtx.encrypt0(key128_token_rs2, coseP.getAlg().AsCBOR());
        ctx3 = CwtCryptoCtx.encrypt0(key128_token_rs3, coseP.getAlg().AsCBOR());
        ctx4 = CwtCryptoCtx.encrypt0(key128_token_rs4, coseP.getAlg().AsCBOR());
        
        switch (testcase) {
        
        /* Client and AS */
        case 1: // Test CoapToken using PSK        	
        	testCoapToken();
        	break;
        	
        case 2: // Test CoapToken using PSK, for asking access to an OSCORE group with a single role, using a REF token.
        	testGroupOSCORESingleRoleREFToken();
        	
        	// === Case 2.1 ===
        	// The requested role is allowed in the specified group

        	// === Case 2.2 ===
        	// The requested role is allowed in the specified group

        	// === Case 2.3 ===
        	// Access to the specified group is not allowed

        	// === Case 2.4 ===
        	// The requested role is not allowed in the specified group

        	// === Case 2.5 ===
        	// The requested role is not allowed in the specified group
        	
        	break;
        	
        case 3: // Test CoapToken using PSK, for asking access to an OSCORE group with multiple roles, using a REF token.
        	testGroupOSCOREMultipleRolesREFToken();
        	
        	// === Case 3.1 ===
        	// Both requested roles are allowed in the specified group

        	// === Case 3.2 ===
        	// Access to the specified group is not allowed

        	// === Case 3.3 ===
        	// Only one role out of the two requested ones is allowed in the specified group
        	
        	break;
        	
        case 4: // Test CoapToken using PSK, for asking access to an OSCORE group with multiple roles, using a REF token.
        	    // (Alternative version with different client)
        	testGroupOSCOREAltClientREFToken();
        	
        	// === Case 4.1 ===
        	// The requested role is not allowed in the specified group

        	// === Case 4.2 ===
        	// Only one role out of the two requested ones is allowed in the specified group
        	
        	break;
        	
        case 5: // Test CoapIntrospect using RPK
        	testCoapIntrospect();
        	break;
        	
        /* Client and Group Manager */
        	
        
        }
        
    }
        
    private static void printResultsFromAS(CoapResponse res) throws Exception {
        if (res != null) {
        	System.out.println("YYYYYYYYYYY");
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
            	CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
                Map<Short, CBORObject> map = Constants.getParams(resCBOR);
                System.out.println(map);
            }
        } else {
        	System.out.println("XXXXXXXXXXXXX It's null!");
            System.out.print("No response received");
        }
    }
    
    private static void printResultsFromRS(CoapResponse res) throws Exception {
        if (res != null) {
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
            	CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
                Map<Short, CBORObject> map = Constants.getParams(resCBOR);
                System.out.println(map);
            }
        } else {
            System.out.print("No response received");
        }
    }
    
    
    // === Case 1 ===
    /**
     * Test CoapToken using PSK
     * 
     * @throws Exception 
     */
    public static void testCoapToken() throws Exception {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientA", key128_client_A));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uri + portNumberAS + "/token");
        client.setEndpoint(e);
        dtlsConnector.start();
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, 
                CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
        */

    }
    
    // M.T.
    // === Case 2 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with a single role, using a REF token.
     * 
     * @throws Exception
     */
    public static void testGroupOSCORESingleRoleREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientF", key128_client_F));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uri + portNumberAS + "/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // === Case 2.1 ===
    	// The requested role is allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        */
        
        // === Case 2.2 ===
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_MONITOR);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        */
        
        // === Case 2.3 ===
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
    	
        byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
        */
        
        // === Case 2.4 ===
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_RESPONDER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
        */
        
        // === Case 2.5 ===
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, (short)10);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add((short)10);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
        */
        
    }
    
    
    // M.T.
    // === Case 3 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * 
     * @throws Exception
     */
    public static void testGroupOSCOREMultipleRolesREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientF", key128_client_F));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uri + portNumberAS + "/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // === Case 3.1 ===
        // Both requested roles are allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// CBORObject cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// cborArrayEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        */
        
        // === Case 3.2 ===
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
        myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
    	// cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_MONITOR);
    	// cborArrayEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
        */
        
        
        // === Case 3.3 ===
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	
        myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayRoles = CBORObject.NewArray();
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_REQUESTER);
    	// cborArrayRoles.Add(Constants.GROUP_OSCORE_RESPONDER);
    	// cborArrayEntry.Add(cborArrayRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        assert(receivedArrayScope.getType().equals(CBORType.Array));
        assert(receivedArrayScope.size() == 1);
        assert(receivedArrayScope.get(0).getType().equals(CBORType.Array));
        assert(receivedArrayScope.get(0).size() == 2);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        int expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(expectedRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	Assert.assertArrayEquals(receivedScope, byteStringScope);
    	*/
        
    }

    
    // M.T.
    // === Case 4 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * (Alternative version with different client)
     * 
     * @throws Exception
     */
    public static void testGroupOSCOREAltClientREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
    	
    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientG", key128_client_G));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uri + portNumberAS + "/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // === Case 4.1 ===
        // The requested role is not allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Constants.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_RESPONDER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
		*/
        
        
        // === Case 4.2 ===
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
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
    	
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        assert(receivedArrayScope.getType().equals(CBORType.Array));
        assert(receivedArrayScope.size() == 1);
        assert(receivedArrayScope.get(0).getType().equals(CBORType.Array));
        assert(receivedArrayScope.get(0).size() == 2);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        int expectedRoles = 0;
        expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(expectedRoles);
    	
    	// OLD VERSION WITH ROLE OR CBOR ARRAY OF ROLES
        // cborArrayEntry.Add(Constants.GROUP_OSCORE_REQUESTER);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	Assert.assertArrayEquals(receivedScope, byteStringScope);
    	*/
            	
    }
    
    
    // === Case 5 ===
    /**
     * Test CoapIntrospect using RPK
     * 
     * @throws Exception
     */
    public static void testCoapIntrospect() throws Exception {
    	
    	CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject RS_x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(rsX));
        CBORObject RS_y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(rsY));
        CBORObject RS_d = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(rsD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), RS_x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), RS_y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), RS_d);
        OneKey key = new OneKey(rpkData);

    	// OLD SETUP
        //OneKey key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        //builder.setPskStore(new StaticPskStore("rs1", key256));
        builder.setIdentity(key.AsPrivateKey(), 
                key.AsPublicKey());
        builder.setRpkTrustAll();
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uri + portNumberAS + "/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();
       
        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, CBORObject.FromObject(at.encode().EncodeToBytes()));
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        printResultsFromAS(response);
        
        /*
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("actuators"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("co2"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));
        */
    }
    
}
