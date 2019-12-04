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
package se.sics.prototype.apps;

import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.OscoreAS;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;
import se.sics.prototype.support.DBHelper;
import se.sics.prototype.support.KeyStorage;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoreAsServer
{
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    
    private static CoapDBConnector db = null;
    private static OscoreAS as = null;
    private static GroupOSCOREJoinPDP pdp = null;
  
    /**
     * The OSCORE AS for testing, autostarted by tests needing this.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key256));
        OneKey tokenPsk = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        OneKey authPsk = new OneKey(keyData);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        Set<String> scopes = new HashSet<>();
        scopes.add("rw_valve");
        scopes.add("r_pressure");
        scopes.add("foobar");
        //Group OSCORE Vinnova prototype scopes
        scopes.add("aaaaaa570000_requester");
        scopes.add("aaaaaa570000_responder");
        scopes.add("aaaaaa570000_monitor");
        scopes.add("aaaaaa570000_requester_responder");
        scopes.add("aaaaaa570000_requester_monitor");
        scopes.add("bbbbbb570000_requester");
        scopes.add("bbbbbb570000_responder");
        scopes.add("bbbbbb570000_monitor");
        scopes.add("bbbbbb570000_requester_responder");
        scopes.add("bbbbbb570000_requester_monitor");
        //End Group OSCORE Vinnova prototype scopes
        Set<String> auds = new HashSet<>();
        auds.add("rs2");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        //COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        COSEparams coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, authPsk, tokenPsk, null);
        
        //Add rs2 as OSCORE Group Manager
        db.addOSCOREGroupManagers("rs2", auds);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, 
                keyTypes, authPsk, null);        
        
        /* --- Configure clients and servers for Vinnova prototype --- */
        
        CBORObject myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Client1")));
        OneKey myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Client1", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Client2")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Client2", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server1")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server1", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server2")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server2", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server3")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server3", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server4")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server4", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server5")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server5", profiles, null, null, 
                keyTypes, myPsk, null); 
        
        
        myKey = CBORObject.NewMap();
        myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server6")));
        myPsk = new OneKey(myKey);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("Server6", profiles, null, null, 
                keyTypes, myPsk, null); 
        /* --- End configure clients and servers for Vinnova prototype --- */
        
        KissTime time = new KissTime();
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Client(cti, "clientA");
        
        OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        pdp = new GroupOSCOREJoinPDP(db);
        
        //Initialize data in PDP
        pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addTokenAccess("clientA");
        pdp.addTokenAccess("clientB");
        pdp.addTokenAccess("clientC");
        pdp.addTokenAccess("clientD");
        pdp.addTokenAccess("clientE");
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        pdp.addIntrospectAccess("rs2");
        pdp.addIntrospectAccess("rs3");
        pdp.addIntrospectAccess("rs5");
        pdp.addIntrospectAccess("rs6");
        pdp.addIntrospectAccess("rs7");

        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        pdp.addAccess("clientA", "rs2", "r_light");
        pdp.addAccess("clientA", "rs2", "r_temp");
        pdp.addAccess("clientA", "rs2", "rw_config");
        pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");
        
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "co2");
        pdp.addAccess("clientB", "rs2", "r_temp");
        pdp.addAccess("clientB", "rs2", "co2");
        pdp.addAccess("clientB", "rs2", "r_light");
        pdp.addAccess("clientB", "rs2", "r_config");
        pdp.addAccess("clientB", "rs2", "failTokenType");
        pdp.addAccess("clientB", "rs3", "rw_valve");
        pdp.addAccess("clientB", "rs3", "r_pressure");
        pdp.addAccess("clientB", "rs3", "failTokenType");
        pdp.addAccess("clientB", "rs3", "failProfile");
        pdp.addAccess("clientB", "rs4", "failProfile");
        pdp.addAccess("clientB", "rs6", "co2");
        pdp.addAccess("clientB", "rs7", "co2");
        
        pdp.addAccess("clientC", "rs3", "r_valve");
        pdp.addAccess("clientC", "rs3", "r_pressure");
        pdp.addAccess("clientC", "rs6", "r_valve");

        pdp.addAccess("clientD", "rs1", "r_temp");
        pdp.addAccess("clientD", "rs1", "rw_config");
        pdp.addAccess("clientD", "rs2", "r_light");
        pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");
        pdp.addAccess("clientD", "rs1", "r_temp");
        

        pdp.addAccess("clientE", "rs3", "rw_valve");
        pdp.addAccess("clientE", "rs3", "r_pressure");
        pdp.addAccess("clientE", "rs3", "failTokenType");
        pdp.addAccess("clientE", "rs3", "failProfile");
        
        /* --- Configure clients and servers for Vinnova prototype --- */
        
        //Add rs2 as OSCORE Group Manager
        Set<String> myAud = new HashSet<>();
        myAud.add("rs2");
        pdp.addOSCOREGroupManagers("rs2", myAud);
        
        pdp.addTokenAccess("Client1");
        pdp.addTokenAccess("Client2");
        pdp.addTokenAccess("Server1");
        pdp.addTokenAccess("Server2");
        pdp.addTokenAccess("Server3");
        pdp.addTokenAccess("Server4");
        pdp.addTokenAccess("Server5");
        pdp.addTokenAccess("Server6");
        
        //Group A
        
        pdp.addAccess("Client1", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Client1", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Client2", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Client2", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server1", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server1", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server2", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server2", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server3", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server3", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server4", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server4", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server5", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server5", "rs2", "aaaaaa570000_requester_responder");
        
        pdp.addAccess("Server6", "rs2", "aaaaaa570000_requester_monitor");
        pdp.addAccess("Server6", "rs2", "aaaaaa570000_requester_responder");
        
        //Group B
        
        pdp.addAccess("Client1", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Client1", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Client2", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Client2", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server1", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server1", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server2", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server2", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server3", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server3", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server4", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server4", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server5", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server5", "rs2", "bbbbbb570000_requester_responder");
        
        pdp.addAccess("Server6", "rs2", "bbbbbb570000_requester_monitor");
        pdp.addAccess("Server6", "rs2", "bbbbbb570000_requester_responder");

        /* --- End configure clients and servers for Vinnova prototype --- */
        
        as = new OscoreAS("AS", db, pdp, time, asymmKey);
        as.start();
        System.out.println("OSCORE AS Server starting on default port.");
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        DBHelper.tearDownDB();
        as.stop();
        pdp.close();
      
    }
    
}
