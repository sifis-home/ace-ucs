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
package se.sics.ace.interop;

import java.util.HashSet;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.DtlsAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Marco Tiloca
 *
 */
public class TestASdtlsProfile
{
	
	/* START LIST OF KEYS */
	
	// PSK authentication key for clientA
    private static byte[] key128_client_A = {(byte)0x61, (byte)0x62, (byte)0x63, (byte)0x04, (byte)0x05, (byte)0x06,
    										 (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										 (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    // More PSKs if needed
    /*
    // PSK authentication key for clientB
    private static byte[] key128_client_B = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06,
    										 (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										 (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    */
    
	// Authentication public key of a Client (client_C)
    private static String cX = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    
    
    // PSK authentication key for the Resource Server rs1
    private static byte[] key128_rs1 = {(byte)0x51, (byte)0x52, (byte)0x53, (byte)0x04, (byte)0x05, (byte)0x06,
						    			(byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
						    			(byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
	// Authentication public key of the Resource Server rs1 (public coordinates)
    private static String rsX = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    
	// PSK to encrypt access tokens issued for Resource Server rs1
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0x04, (byte)0x05, (byte)0x06,
    										  (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										  (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};

    
    // Authentication asymmetric key pair of the AS (public and private coordinates)
    private static String asX = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
	private static String asD = "0089A92D07B34F1D806FABFF444AF6507C5F18F47BB2CCFAA7FBEC447303790D53";
    
    
    /* END LIST OF KEYS */
	
    
    private static CoapDBConnector db = null;
    private static DtlsAS as = null;
    private static KissPDP pdp = null;
    
    private static int portNumber = 5689;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        // Setup the PSK authentication key for clientA
        CBORObject keyData = CBORObject.NewMap();
        String kidStr = "PSK_clientA";
        byte[] kidBytes = kidStr.getBytes(Constants.charset);
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_A));
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kidBytes);
        OneKey authPsk_clientA = new OneKey(keyData);
        
        /*
        // Setup the PSK authentication key for clientB
        keyData = CBORObject.NewMap();
        kidStr = "PSK_clientB";
        kidBytes = kidStr.getBytes(Constants.charset);
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_B));
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kidBytes);
        OneKey authPsk_clientB = new OneKey(keyData);
        */
        
        
        // Setup the authentication public key of clientC
        CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject C_x = CBORObject.FromObject(hexString2byteArray(cX));
        CBORObject C_y = CBORObject.FromObject(hexString2byteArray(cY));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), C_x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), C_y);
        OneKey akey_c = new OneKey(rpkData);
        
        
        // Setup the PSK authentication key for the Resource Server rs1
        keyData = CBORObject.NewMap();
        kidStr = "PSK_rs1";
        kidBytes = kidStr.getBytes(Constants.charset);
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_rs1));
        OneKey authPsk_rs1 = new OneKey(keyData);
        
        // Setup the authentication public key of the Resource Server rs1
        rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject rs_x = CBORObject.FromObject(hexString2byteArray(rsX));
        CBORObject rs_y = CBORObject.FromObject(hexString2byteArray(rsY));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), rs_x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), rs_y);
        OneKey akey_rs = new OneKey(rpkData);
        
        // Setup the PSK to encrypt access tokens issued for Resource Server rs1
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs1));
        OneKey tokenPsk_rs1 = new OneKey(keyData);
       
        
        // Setup the authentication asymmetric key pair of the AS
        rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject as_x = CBORObject.FromObject(hexString2byteArray(asX));
        CBORObject as_y = CBORObject.FromObject(hexString2byteArray(asY));
        CBORObject as_d = CBORObject.FromObject(hexString2byteArray(asD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), as_x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), as_y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), as_d);
        OneKey asRPK = new OneKey(rpkData);  

        
        // Register the Resource Server rs1
        
        // Set supported ACE profiles
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        
        // Set supported scopes
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("r_config");
        scopes.add("rw_config");
        scopes.add("foobar");
        
        // Set audiences
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        
        // Set supported types of proof-of-possession keys
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");

        // Set supported types of access tokens
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        
        // Set COSE context to protect issued access tokens
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        cose.add(coseP);
        
        // Set lifetime for issued access tokens
        long expiration = 30000L;        
        
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, authPsk_rs1, tokenPsk_rs1, akey_rs);
        

        // Register the client clientA

        // Set supported ACE profiles
        profiles.clear();
        profiles.add("coap_dtls");

        // Set supported types of proof-of-possession keys
        keyTypes.clear();
        keyTypes.add("PSK");

        db.addClient("clientA", profiles, null, null, keyTypes, authPsk_clientA, null);
        

        /*
        // Register the client clientB

        // Set supported ACE profiles
        profiles.clear();
        profiles.add("coap_dtls");

        // Set supported types of proof-of-possession keys
        keyTypes.clear();
        keyTypes.add("PSK");

        db.addClient("clientB", profiles, null, null, keyTypes, authPsk_clientB, null);
		*/
        
        
        // Register the client clientC

        // Set supported ACE profiles
        profiles.clear();
        profiles.add("coap_dtls");

        // Set supported types of proof-of-possession keys
        keyTypes.clear();
        keyTypes.add("RPK");

        db.addClient("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", profiles, null, null, keyTypes, null, akey_c);
        
        
        //Setup time provider
        KissTime time = new KissTime();
        
                
        //Initialize data in PDP
        pdp = new KissPDP(db);
        
        // Allow accesses to the /introspect endpoint
        pdp.addIntrospectAccess("ni:///sha-256;sU09Kz-RXT8izVvD3n7v3d5vHVGF1NcYShZZ-oczcVE");
        pdp.addIntrospectAccess("rs1");

        // Allow accesses to the /token endpoint
        pdp.addTokenAccess("clientA");
        // pdp.addTokenAccess("clientB");
        pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w"); // clientC

        // Configure access policies for clientA
        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        
        /*
        // Configure access policies for clientB
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "rw_config");
        */
        
        // Configure access policies for clientC
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "r_temp");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "rw_config");
        
        
        // Create and start the AS
        as = new DtlsAS("AS", db, pdp, time, asRPK, portNumber);
        as.start();
        System.out.println("Server starting");
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        as.stop();
        pdp.close();
        DBHelper.tearDownDB();
    }
    
    /**
     * Reads the keys and transforms to bytes from Strings.
     * 
     * @param hex  the hex String representation of a key
     * @return  the byte array representation
     */
    public static byte[] hexString2byteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
}
