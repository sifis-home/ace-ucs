/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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

import org.apache.log4j.BasicConfigurator;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.DBHelper;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.CoapsAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz
 *
 */
public class PlugtestAS {

    private static byte[] key128 = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static byte[] key256 = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20};

    private static String asX 
        = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY 
        = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
    private static String asD 
        = "0089A92D07B34F1D806FABFF444AF6507C5F18F47BB2CCFAA7FBEC447303790D53";
                     
    private static String rsX 
        = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY 
        = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    
    private static String cX 
        = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY 
        = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";

    
    private static CoapDBConnector db = null;
    private static CoapsAS as = null; 
    private static KissPDP pdp = null;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        BasicConfigurator.configure();

        CBORObject asRpkData = CBORObject.NewMap();
        asRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        asRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        asRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject x = CBORObject.FromObject(hexString2byteArray(asX));
        CBORObject y = CBORObject.FromObject(hexString2byteArray(asY));
        CBORObject d = CBORObject.FromObject(hexString2byteArray(asD));
        asRpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
        asRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
        asRpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
        OneKey asKey = new OneKey(asRpkData);  
        
        CBORObject rsRpkData = CBORObject.NewMap();
        rsRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rsRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rsRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject rs_x = CBORObject.FromObject(hexString2byteArray(rsX));
        CBORObject rs_y = CBORObject.FromObject(hexString2byteArray(rsY));
        rsRpkData.Add(KeyKeys.EC2_X.AsCBOR(), rs_x);
        rsRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), rs_y);
        OneKey rsKey = new OneKey(rsRpkData);
        
        CBORObject cRpkData = CBORObject.NewMap();
        cRpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cRpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        cRpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject c_x = CBORObject.FromObject(hexString2byteArray(cX));
        CBORObject c_y = CBORObject.FromObject(hexString2byteArray(cY));
        cRpkData.Add(KeyKeys.EC2_X.AsCBOR(), c_x);
        cRpkData.Add(KeyKeys.EC2_Y.AsCBOR(), c_y);
        OneKey cKey = new OneKey(cRpkData);
                
        //Just to be sure no old test pollutes the DB
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();
        
        CBORObject keyDataC = CBORObject.NewMap();
        keyDataC.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataC.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        OneKey clientPSK = new OneKey(keyDataC);
        
        CBORObject keyDataRS = CBORObject.NewMap();
        keyDataRS.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataRS.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key256));
        OneKey rsPSK = new OneKey(keyDataRS);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> scopes = new HashSet<>();
        scopes.add("HelloWorld");
        scopes.add("r_Lock");
        scopes.add("rw_Lock");
        Set<String> auds = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;
        db.addRS("coap://localhost", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, rsPSK, rsKey);
                
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, 
                keyTypes, clientPSK, cKey);        
        
        KissTime time = new KissTime();
        pdp = new KissPDP(db);
        
        //Initialize data in PDP
        pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addTokenAccess("clientA");
       
        pdp.addAccess("clientA", "rs1", "HelloWorld");
        pdp.addAccess("clientA", "rs1", "r_Lock");
        pdp.addAccess("clientA", "rs1", "rw_Lock");
        
        as = new CoapsAS("AS", db, pdp, time, asKey);
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
    }
    
    
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
