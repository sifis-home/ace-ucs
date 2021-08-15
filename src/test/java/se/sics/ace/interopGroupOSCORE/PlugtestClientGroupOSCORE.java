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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.Util;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Marco Tiloca
 *
 */
public class PlugtestClientGroupOSCORE {
    
	/* START LIST OF KEYS */
	
	// For old tests
    private static byte[] key128_client_A = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
	// More PSKs if needed
	/*
    private static byte[] key128_client_B = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_C = {0x41, 0x42, 0x43, 0x04, 0x05, 0x06, 0x07,
    		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_D = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static OneKey clientA_PSK = null;
    private static OneKey clientB_PSK = null;
    private static OneKey clientC_PSK = null;
    private static OneKey clientD_PSK = null;
    */
    
    // For group joining tests
    private static byte[] key128_client_F = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};
    private static OneKey clientF_PSK = null;
    private static byte[] key128_client_G = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    private static OneKey clientG_PSK = null;

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
    static OneKey rsRPK = null;
    
    // Asymmetric keys of the AS
    private static String asX = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
    static OneKey asRPK = null;
    
	// Asymmetric key pair of a Client (client3) for DTLS handshakes only
    private static String cX = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    private static String cD = "00A43BAA7ED22FF2699BA62CA4999359B146F065A95C4E46017CD25EB89A94AD29";
    static OneKey cRPK = null;
    
	// Sender ID 0x52 for an already present group member
	private static final byte[] idClient2 = new byte[] { (byte) 0x52 };
	
	// Sender ID 0x77 for an already present group member
	private static final byte[] idClient3 = new byte[] { (byte) 0x77 };
    
    /* ECDSA_256 keys */
    /* */
    // Asymmetric key pair of the Client joining the OSCORE group (ECDSA_256)
    private static String c1X_ECDSA = "E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC";
    private static String c1Y_ECDSA = "164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE";
    private static String c1D_ECDSA = "3BE0047599B42AA44B8F8A0FA88D4DA11697B58D9FCC4E39443E9843BF230586";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient2' (ECDSA_256)
    private static String c2X_ECDSA = "35F3656092E1269AAAEE6262CD1C0D9D38ED78820803305BC8EA41702A50B3AF";
    private static String c2Y_ECDSA = "5D31247C2959E7B7D3F62F79622A7082FF01325FC9549E61BB878C2264DF4C4F";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient3' (ECDSA_256)
    private static String c3X_ECDSA = "9DFA6D63FD1515761460B7B02D54F8D7345819D2E5576C160D3148CC7886D5F1";
    private static String c3Y_ECDSA = "76C81A0C1A872F1730C10317AB4F3616238FB23A08719E8B982B2D9321A2EF7D";
    
    // Public key of the Group Manager (ECDSA_256)
    private static String gmX_ECDSA = "2236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540";
    private static String gmY_ECDSA = "770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B";
    /* */
    /* */
    
    
    /* Ed25519 keys */
    /* */
    // Asymmetric key pair of the Client joining the OSCORE group (Ed25519)
    private static String c1X_EDDSA = "069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A";
    private static String c1D_EDDSA = "64714D41A240B61D8D823502717AB088C9F4AF6FC9844553E4AD4C42CC735239";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient2' (Ed25519)
    private static String c2X_EDDSA = "77EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient3' (Ed25519)
    private static String c3X_EDDSA = "105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E";
    
    // Public key of the Group Manager (Ed25519)
    private static String gmX_EDDSA = "C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3";
    /* */
    /* */
    
    private static OneKey C1keyPair = null;
    private static OneKey C2pubKey = null;
    private static OneKey C3pubKey = null;
    private static OneKey gmPubKey = null;
    
    /* END LIST OF KEYS */
    
    // For old tests
    /*
    private static byte[] kid1 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBC};
    private static byte[] kid2 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBD};
    private static byte[] kid3 = 
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBE};
    private static byte[] kid4 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xBF};
	*/

    // For group joining tests
    private static byte[] kid6 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xAA};
    private static byte[] kid7 =
        {(byte)0x91, (byte)0xEC, (byte)0xB5, (byte)0xCB, 0x5D, (byte)0xAB};
    
    //Needed to show token content
    private static CwtCryptoCtx ctx1 = null;
    
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
    
    private static String rsAddr = "";
    private static String rsAuthzInfo = "";
    private static final String rootGroupMembershipResource = "ace-group";
    private static final String groupName = new String("feedca570000");
    
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set curve X25519 for pairwise key derivation
    private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();
    
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
        
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 1);
    	Security.insertProviderAt(EdDSA, 0);
        
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
        cRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(
        		cRPK.AsPublicKey()).getName();
        cRPK.add(KeyKeys.KeyId, CBORObject.FromObject(
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
        rsRPK = new OneKey(rsRpkData);
        
        // Setup the asymmetric key pair of the joining node
    	// ECDSA_256
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.ECDSA_256.AsCBOR());
            rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c1X_ECDSA));
            y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c1Y_ECDSA));
            d = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c1D_ECDSA));
            rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
            rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
            rpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
            C1keyPair = new OneKey(rpkData);
       	}
    	// EDDSA (Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.EDDSA.AsCBOR());
            rpkData.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c1X_EDDSA));
            d = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c1D_EDDSA));
            rpkData.Add(KeyKeys.OKP_X.AsCBOR(), x);
            rpkData.Add(KeyKeys.OKP_D.AsCBOR(), d);
            C1keyPair = new OneKey(rpkData);
    	}
        
        // Setup the public key of the group members
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.ECDSA_256.AsCBOR());
            rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c2X_ECDSA));
            y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c2Y_ECDSA));
            rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
            rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
            C2pubKey = new OneKey(rpkData);
            
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.ECDSA_256.AsCBOR());
            rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c3X_ECDSA));
            y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c3Y_ECDSA));
            rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
            rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
            C3pubKey = new OneKey(rpkData);     
            
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.ECDSA_256.AsCBOR());
            rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(gmX_ECDSA));
            y = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(gmY_ECDSA));
            rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
            rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
            gmPubKey = new OneKey(rpkData); 
       	}
    	// EDDSA (Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.EDDSA.AsCBOR());
            rpkData.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c2X_EDDSA));
            rpkData.Add(KeyKeys.OKP_X.AsCBOR(), x);
            C2pubKey = new OneKey(rpkData);
            
            rpkData = CBORObject.NewMap();
            rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
            rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                    AlgorithmID.EDDSA.AsCBOR());
            rpkData.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
            x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(c3X_EDDSA));
            rpkData.Add(KeyKeys.OKP_X.AsCBOR(), x);
            C3pubKey = new OneKey(rpkData);
            
            rpkData = CBORObject.NewMap();
			rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
			rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
			        AlgorithmID.EDDSA.AsCBOR());
			rpkData.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
			x = CBORObject.FromObject(PlugtestASGroupOSCORE.hexString2byteArray(gmX_EDDSA));
			rpkData.Add(KeyKeys.OKP_X.AsCBOR(), x);
			gmPubKey = new OneKey(rpkData);
    	}
        //
        
        //Setup PSKs
    	
    	// More PSKs if needed
    	/*
        CBORObject pskData = CBORObject.NewMap();
        pskData.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_A));
        pskData.Add(KeyKeys.KeyId.AsCBOR(), kid1);
        clientA_PSK = new OneKey(pskData);
        
        CBORObject pskData2 = CBORObject.NewMap();
        pskData2.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData2.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_B));
        pskData2.Add(KeyKeys.KeyId.AsCBOR(), kid2);
        clientB_PSK = new OneKey(pskData2);
       
        CBORObject pskData3 = CBORObject.NewMap();
        pskData3.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData3.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_C));
        pskData3.Add(KeyKeys.KeyId.AsCBOR(), kid3);
        clientC_PSK = new OneKey(pskData3);
        
        CBORObject pskData4 = CBORObject.NewMap();
        pskData4.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData4.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_D));
        pskData4.Add(KeyKeys.KeyId.AsCBOR(), kid4);
        clientD_PSK = new OneKey(pskData4);
        */
        
        CBORObject pskData6 = CBORObject.NewMap();
        pskData6.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData6.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_F));
        pskData6.Add(KeyKeys.KeyId.AsCBOR(), kid6);
        clientF_PSK = new OneKey(pskData6);
        
        CBORObject pskData7 = CBORObject.NewMap();
        pskData7.Add(KeyKeys.KeyType.AsCBOR(), 
                KeyKeys.KeyType_Octet);
        pskData7.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128_client_G));
        pskData7.Add(KeyKeys.KeyId.AsCBOR(), kid7);
        clientG_PSK = new OneKey(pskData7);
        
        int testcase = Integer.parseInt(args[0]);
        
        rsAddr = new String(args[1]);
        uri = new String(args[1]); 
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
        	
        case 6: // Test post to authz-info with RPK then request for accessing an OSCORE Group with single role
        	testPostRPKGroupOSCORESingleRole();
        	break;
        	
        case 7: // Test post to authz-info with RPK then request for accessing an OSCORE Group with multiple roles
        	testPostRPKGroupOSCOREMultipleRoles();
        	break;
        	
        case 8: // Test post to authz-info with PSK then request for accessing an OSCORE Group with single role
        	testPostPSKGroupOSCORESingleRole();
        	break;
        	
        case 9: // Test post to authz-info with PSK then request for accessing an OSCORE Group with multiple roles
        	testPostPSKGroupOSCOREMultipleRoles();
        	break;
        	
        default:
        	/*
    	    // Private and public key to be used in the OSCORE group (ECDSA_256)
    	    String groupKeyPair = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
    	    
    	    // Public key to be received for the group member with Sender ID 'idClient2' (ECDSA_256)
    	    String strPublicKeyPeer1 = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
    	    
    	    // Public key to be received for the group member with Sender ID 'idClient3' (ECDSA_256)
    	    String strPublicKeyPeer2 = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
            
    	    OneKey cMember1 = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(groupKeyPair)));
    	    OneKey cMember2 = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer1)));
    	    OneKey cMember3 = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(strPublicKeyPeer2))).PublicKey();
    	    
    	    System.out.println(cMember1.AsCBOR().toString());
    	    System.out.println(cMember2.AsCBOR().toString());
    	    System.out.println(cMember3.AsCBOR().toString());
    	    */
    	    break;
        }
        
    }
    
    private static void printResponseFromAS(CoapResponse res) throws Exception {
        if (res != null) {
        	System.out.println("*** Response from the AS *** ");
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
            	CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
                Map<Short, CBORObject> map = Constants.getParams(resCBOR);
                System.out.println(map);
            }
        } else {
        	System.out.println("*** The response from the AS is null!");
            System.out.print("No response received");
        }
    }

    private static void printMapPayload(CBORObject obj) throws Exception {
        if (obj != null) {
        	System.out.println("*** Map Payload *** ");
                System.out.println(obj);
        } else {
        	System.out.println("*** The payload argument is null!");
        }
    }
    
    private static void printResponseFromRS(CoapResponse res) throws Exception {
        if (res != null) {
        	System.out.println("*** Response from the RS *** ");
            System.out.print(res.getCode().codeClass + "." 
                    + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
            	CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
                Map<Short, CBORObject> map = Constants.getParams(resCBOR);
                System.out.println(map);
            }
        } else {
        	System.out.println("*** The response from the RS is null!");
            System.out.print("No response received");
        }
    }
    
    
    // Start tests with the AS
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
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);

    }
    
    // === Case 2 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with a single role, using a REF token.
     * 
     * @throws Exception
     */
    public static void testGroupOSCORESingleRoleREFToken() throws Exception { 
        
    	String gid = groupName;
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        
        // === Case 2.2 ===
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);

        
        // === Case 2.3 ===
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
        byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        
        // === Case 2.4 ===
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);

        
        // === Case 2.5 ===
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, (short)10);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
    }
    
    
    // === Case 3 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * 
     * @throws Exception
     */
    public static void testGroupOSCOREMultipleRolesREFToken() throws Exception { 
        
    	String gid = groupName;
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        
        // === Case 3.2 ===
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        
        // === Case 3.3 ===
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
               
    }

    
    // === Case 4 ===
    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * (Alternative version with different client)
     * 
     * @throws Exception
     */
    public static void testGroupOSCOREAltClientREFToken() throws Exception { 
        
    	String gid = groupName;
    	
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
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        
        // === Case 4.2 ===
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
            	
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
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
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
                Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);

    }
    // End tests with the AS
    
    
    // Start tests with the Group Manager
    
    // === Case 6 ===
    /** 
     * Test post to authz-info with RPK then request
     * for accessing an OSCORE Group with single role
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    public static void testPostRPKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException, Exception {
        Map<Short, CBORObject> params = new HashMap<>();
    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
    	
    	cborArrayScope.Add(scopeEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostRPKGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, cRPK.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        rsAuthzInfo =  "coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info";
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAuthzInfo, payload, null);
        
        printResponseFromRS(r);
        
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        
        /*
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        */
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        byte[] gm_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	
        	// The algorithm capabilities
        	signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	
        	// The key type capabilities
        	signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	
        	 // The algorithm capabilities
        	signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	
        	 // The key type capabilities
        	signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
     // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();

        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        final CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        /*
        if (askForSignInfo) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        if (askForEcdhInfo) {
		    Assert.assertEquals(false, cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
		    
		    if (cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
		    
		        Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
		        ecdhInfo = CBORObject.NewArray();
		        ecdhInfo = cbor.get(CBORObject.FromObject(Constants.ECDH_INFO));
		        
		        CBORObject ecdhInfoExpected = CBORObject.NewArray();
		        CBORObject ecdhInfoEntry = CBORObject.NewArray();
		        
		        ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		        
		        if (ecdhAlgExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhAlgExpected);
		        
		        if (ecdhParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhParamsExpected);
		        
		        if (ecdhKeyParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhKeyParamsExpected);
		        
		        if (pubKeyEncExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(pubKeyEncExpected);
		        
		        ecdhInfoExpected.Add(ecdhInfoEntry);
		
		        Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
		        
		    }
		}
        */
        
        
        CoapClient c = DTLSProfileRequests.getRpkClient(cRPK, rsRPK);
        c.setURI("coaps://" + rsAddr + ":" + portNumberRSsec + "/" + rootGroupMembershipResource + "/" + groupName);
        
        CBORObject requestPayload = CBORObject.NewMap();

        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayScope.Add(myRoles);
    	    	
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members 
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty

        	requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
        	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
        	if (gm_nonce == null)
        		Assert.fail("Error: the component N_S of the signature challence is null");
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = C1keyPair.PublicKey();
        	
        	requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
        	
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
                   	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2);
        

        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));

        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        
        
    	final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
    	final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
    	final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;

    	AlgorithmID signAlg = null;
    	
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }

        signParams.Add(algCapabilities);
        signParams.Add(keyCapabilities);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        	Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        	Assert.assertEquals(2, coseKeySetArray.size());
        	
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
        	Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
        	Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        	
        	byte[] peerSenderId;
        	OneKey peerPublicKey;
        	byte[] peerSenderIdFromResponse;
        	

        	peerSenderId = idClient3;
        	peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        	peerPublicKey = C3pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
        	
        	peerSenderId = idClient2;
        	peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        	peerPublicKey = C2pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
        	
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        	
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
			Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
		Assert.assertArrayEquals(gmPubKey.AsCBOR().EncodeToBytes(),
		                            joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        */
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();

        CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
        byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();

        CBORObject kdcCredCBOR = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        CBORObject gmPublicKeyCBOR = CBORObject.DecodeFromBytes(kdcCredCBOR.GetByteString());
        PublicKey gmPublicKey = new OneKey(gmPublicKeyCBOR).AsPublicKey();

        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
            Assert.fail("Invalid GM's PoP evidence");
        }
        
    }
    
    // === Case 7 ===
    /** 
     * Test post to authz-info with RPK then request
     * for accessing an OSCORE Group with multiple roles
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    public static void testPostRPKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException, Exception {
        Map<Short, CBORObject> params = new HashMap<>();
    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject scopeEntry = CBORObject.NewArray();
    	scopeEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	cborArrayScope.Add(scopeEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostRPKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, cRPK.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        rsAuthzInfo =  "coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info";
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAuthzInfo, payload, null);
        printResponseFromRS(r);
        
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        
        /*
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostRPKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        */
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
        	
        	// The algorithm capabilities
        	signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	
        	// The key type capabilities
        	signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        	signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
        	
        	 // The algorithm capabilities
        	signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	
        	 // The key type capabilities
        	signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        	signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();

        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        final CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        /*
        if (askForSignInfo) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        if (askForEcdhInfo) {
		    Assert.assertEquals(false, cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
		    
		    if (cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
		    
		        Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
		        ecdhInfo = CBORObject.NewArray();
		        ecdhInfo = cbor.get(CBORObject.FromObject(Constants.ECDH_INFO));
		        
		        CBORObject ecdhInfoExpected = CBORObject.NewArray();
		        CBORObject ecdhInfoEntry = CBORObject.NewArray();
		        
		        ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		        
		        if (ecdhAlgExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhAlgExpected);
		        
		        if (ecdhParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhParamsExpected);
		        
		        if (ecdhKeyParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhKeyParamsExpected);
		        
		        if (pubKeyEncExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(pubKeyEncExpected);
		        
		        ecdhInfoExpected.Add(ecdhInfoEntry);
		
		        Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
		        
		    }
		}
        */
        
        CoapClient c = DTLSProfileRequests.getRpkClient(cRPK, rsRPK);
        c.setURI("coaps://" + rsAddr + ":" + portNumberRSsec + "/" + rootGroupMembershipResource + "/" + groupName);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);
    	
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = C1keyPair.PublicKey();
        	
        	requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
        	
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
       	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2);
        

        Assert.assertEquals("CREATED", r2.getCode().name());

        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));


    	final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
    	final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
    	final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
    	
    	AlgorithmID signAlg = null;
    	
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        CBORObject signKeyParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }

        signParams.Add(algCapabilities);
        signParams.Add(keyCapabilities);
        signKeyParams = keyCapabilities;
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        	Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        	Assert.assertEquals(2, coseKeySetArray.size());
        	
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
			Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
			Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        	
        	byte[] peerSenderId;
        	OneKey peerPublicKey;
        	byte[] peerSenderIdFromResponse;
        	
        	peerSenderId = idClient3;
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        	peerPublicKey = C3pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
        	
        	peerSenderId = idClient2;
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        	peerPublicKey = C2pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
        	// ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            
            expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        	
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
		Assert.assertArrayEquals(gmPubKey.AsCBOR().EncodeToBytes(),
		                            joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        */
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();

        CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
        byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();

        CBORObject kdcCredCBOR = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        CBORObject gmPublicKeyCBOR = CBORObject.DecodeFromBytes(kdcCredCBOR.GetByteString());
        PublicKey gmPublicKey = new OneKey(gmPublicKeyCBOR).AsPublicKey();

        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
            Assert.fail("Invalid GM's PoP evidence");
        }
        
    }
    
    // === Case 8 ===
    /** 
     * Test post to authz-info with PSK then request
     * for joining an OSCORE Group with a single role
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    public static void testPostPSKGroupOSCORESingleRole() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException, Exception {               
        Map<Short, CBORObject> params = new HashMap<>();
        String groupName = new String("feedca570000");
        boolean askForSignInfo = true;
        boolean askForEcdhInfo = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
    	
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
        int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	scopeEntry.Add(myRoles);
        
        cborArrayScope.Add(scopeEntry);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostPSKGOSR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, clientF_PSK.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        rsAuthzInfo =  "coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info";
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAuthzInfo, payload, null);
        printResponseFromRS(r);
        
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        
        /*
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        
        Assert.assertArrayEquals("tokenPostPSKGOSR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        */
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
                // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
                // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();

        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        final CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        /*
        if (askForSignInfo) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        if (askForEcdhInfo) {
		    Assert.assertEquals(false, cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
		    
		    if (cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
		    
		        Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
		        ecdhInfo = CBORObject.NewArray();
		        ecdhInfo = cbor.get(CBORObject.FromObject(Constants.ECDH_INFO));
		        
		        CBORObject ecdhInfoExpected = CBORObject.NewArray();
		        CBORObject ecdhInfoEntry = CBORObject.NewArray();
		        
		        ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		        
		        if (ecdhAlgExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhAlgExpected);
		        
		        if (ecdhParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhParamsExpected);
		        
		        if (ecdhKeyParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhKeyParamsExpected);
		        
		        if (pubKeyEncExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(pubKeyEncExpected);
		        
		        ecdhInfoExpected.Add(ecdhInfoEntry);
		
		        Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
		        
		    }
		}
        */
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress(rsAddr, 
                		portNumberRSsec), 
                kid6,
                clientF_PSK);
        
        c.setURI("coaps://" + rsAddr + ":" + portNumberRSsec + "/" + rootGroupMembershipResource + "/" + groupName);
        CBORObject requestPayload = CBORObject.NewMap();

        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayScope.Add(myRoles);
    	        
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members 
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty

        	requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = C1keyPair.PublicKey();
        	
        	requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
        	
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
       	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2);
        

        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
       
                
    	final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
    	final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
    	final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
    	
    	AlgorithmID signAlg = null;
    	
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }

        signParams.Add(algCapabilities);
        signParams.Add(keyCapabilities);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        	Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        	Assert.assertEquals(2, coseKeySetArray.size());
        	
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
			Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
			Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        	
        	byte[] peerSenderId;
        	OneKey peerPublicKey;
        	byte[] peerSenderIdFromResponse;
        	
        	peerSenderId = idClient3;
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        	peerPublicKey = C3pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
        	
        	peerSenderId = idClient2;
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        	peerPublicKey = C2pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
            
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        	
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
		Assert.assertArrayEquals(gmPubKey.AsCBOR().EncodeToBytes(),
		                            joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        */
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();

        CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
        byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();

        CBORObject kdcCredCBOR = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        CBORObject gmPublicKeyCBOR = CBORObject.DecodeFromBytes(kdcCredCBOR.GetByteString());
        PublicKey gmPublicKey = new OneKey(gmPublicKeyCBOR).AsPublicKey();

        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
            Assert.fail("Invalid GM's PoP evidence");
        }
        
    }
    
    // === Case 9 ===
    /** 
     * Test post to authz-info with PSK then request
     * for joining an OSCORE Group with multiple roles
     * @throws CoseException 
     * @throws AceException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IOException 
     * @throws ConnectorException 
     */
    public static void testPostPSKGroupOSCOREMultipleRoles() throws CoseException, IllegalStateException, 
            InvalidCipherTextException, AceException, ConnectorException, IOException, Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        String groupName = new String("feedca570000");
    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
    	boolean askForPubKeys = true;
    	boolean providePublicKey = true;
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject scopeEntry = CBORObject.NewArray();
        scopeEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	scopeEntry.Add(myRoles);
    	
    	cborArrayScope.Add(scopeEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("rs2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "tokenPostPSKGOMR".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, clientF_PSK.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload;
        
        // The payload is a CBOR including also the Access Token
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1));
        if (askForSignInfo)
        	payload.Add(Constants.SIGN_INFO, CBORObject.Null);
        
        rsAuthzInfo =  "coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info";
        
        CoapResponse r = DTLSProfileRequests.postToken(rsAuthzInfo, payload, null);
        
        printResponseFromRS(r);
        
        CBORObject cbor = CBORObject.DecodeFromBytes(r.getPayload());
        
        /*
        Assert.assertNotNull(cbor);
        CBORObject cti = cbor.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals("tokenPostPSKGOMR".getBytes(Constants.charset), 
                cti.GetByteString());
        
        Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.KDCCHALLENGE)));
        Assert.assertEquals(CBORType.ByteString, cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).getType());
        */
        
        // Nonce from the GM, to be signed together with a local nonce to prove PoP of the private key
        byte[] gm_sign_nonce = cbor.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
                // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
                // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();

        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        
        final CBORObject pubKeyEncExpected = CBORObject.FromObject(Constants.COSE_KEY);
        
        /*
        if (askForSignInfo) {
        	Assert.assertEquals(true, cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = cbor.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (pubKeyEncExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(pubKeyEncExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfo, signInfoExpected);
        }
        
        if (askForEcdhInfo) {
		    Assert.assertEquals(false, cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
		    
		    if (cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
		    
		        Assert.assertEquals(CBORType.Array, cbor.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
		        ecdhInfo = CBORObject.NewArray();
		        ecdhInfo = cbor.get(CBORObject.FromObject(Constants.ECDH_INFO));
		        
		        CBORObject ecdhInfoExpected = CBORObject.NewArray();
		        CBORObject ecdhInfoEntry = CBORObject.NewArray();
		        
		        ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		        
		        if (ecdhAlgExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhAlgExpected);
		        
		        if (ecdhParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhParamsExpected);
		        
		        if (ecdhKeyParamsExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(ecdhKeyParamsExpected);
		        
		        if (pubKeyEncExpected == null)
		            ecdhInfoEntry.Add(CBORObject.Null);
		        else
		            ecdhInfoEntry.Add(pubKeyEncExpected);
		        
		        ecdhInfoExpected.Add(ecdhInfoEntry);
		
		        Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
		        
		    }
		}
        */
        
        CoapClient c = DTLSProfileRequests.getPskClient(
                new InetSocketAddress(rsAddr, 
                		portNumberRSsec), 
                kid6,
                clientF_PSK);
        
        c.setURI("coaps://" + rsAddr + ":" + portNumberRSsec + "/" + rootGroupMembershipResource + "/" + groupName);
        CBORObject requestPayload = CBORObject.NewMap();

        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);

    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        if (askForPubKeys) {
        	
            CBORObject getPubKeys = CBORObject.NewArray();
            
            getPubKeys.Add(CBORObject.True); // This must be true
            
            getPubKeys.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys of both the already present group members 
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getPubKeys.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getPubKeys.get(1).Add(myRoles);
            
            getPubKeys.Add(CBORObject.NewArray()); // This must be empty

        	requestPayload.Add(Constants.GET_PUB_KEYS, getPubKeys);
        	
        }
        
        if (providePublicKey) {
        	
        	// For the time being, the client's public key can be only a COSE Key
        	OneKey publicKey = C1keyPair.PublicKey();
        	
        	requestPayload.Add(Constants.CLIENT_CRED, publicKey.AsCBOR().EncodeToBytes());
        	
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_sign_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
       	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
        	
        }
        
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.post(requestPayload.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2);
        

        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
        
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        // Sanity check
    	Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
       
        // Check the presence, type and value of the signature key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)).getType());
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_KEY), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));
       
        
    	final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
    	final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
    	final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	final AlgorithmID hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
    	
    	AlgorithmID signAlg = null;
    	
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        	signAlg = AlgorithmID.ECDSA_256;
        	algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        	keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
        
        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
        	signAlg = AlgorithmID.EDDSA;
        	algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        	keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }

        signParams.Add(algCapabilities);
        signParams.Add(keyCapabilities);
    	
    	Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
    	Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
    	
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HKDF_HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
        	myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        
        if (askForPubKeys) {
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).getType());
        	
        	// The content of the byte string should be a COSE_KeySet, to be processed accordingly
        	
        	byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        	CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);
        	Assert.assertEquals(CBORType.Array, coseKeySetArray.getType());
        	Assert.assertEquals(2, coseKeySetArray.size());
        	
        	Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
			Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
			Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
        	
        	byte[] peerSenderId;
        	OneKey peerPublicKey;
        	byte[] peerSenderIdFromResponse;
        	
        	peerSenderId = new byte[] { (byte) 0x77 };
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
        	peerPublicKey = C3pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        	
        	// ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(0).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(0).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(0).get(KeyKeys.OKP_X.AsCBOR()));
            }
        	
        	peerSenderId = new byte[] { (byte) 0x52 };
        	peerSenderIdFromResponse = joinResponse.
                            get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
        	peerPublicKey = C2pubKey;
        	Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, coseKeySetArray.get(1).get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, coseKeySetArray.get(1).get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), coseKeySetArray.get(1).get(KeyKeys.OKP_X.AsCBOR()));
            }
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            
            expectedRoles = 0;
            expectedRoles = Constants.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
        	
        }
        else {
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS)));
        	Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
		Assert.assertArrayEquals(gmPubKey.AsCBOR().EncodeToBytes(),
		                            joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString());
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        */
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();

        CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
        byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();

        CBORObject kdcCredCBOR = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED));
        CBORObject gmPublicKeyCBOR = CBORObject.DecodeFromBytes(kdcCredCBOR.GetByteString());
        PublicKey gmPublicKey = new OneKey(gmPublicKeyCBOR).AsPublicKey();

        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
            Assert.fail("Invalid GM's PoP evidence");
        }
        
}
    
    // End tests with the Group Manager
    
}
