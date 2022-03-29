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
package se.sics.ace.coap.dtlsProfile.observe;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.CoAP;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.PDP;
import se.sics.ace.as.TrlConfig;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.DtlsAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.ucs.UcsHelper;

import java.util.*;

/**
 * Authorization Server to test with DtlsProtObserveCTestClient
 *
 * @author Marco Rasori
 *
 */
public class DtlsProtObserveASTestServer
{
    /**
     * Symmetric key for the psk shared with the client
     */
    static byte[] key128Client = {'C', '-', 'A', 'S', ' ', 'P', 'S', 'K', 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * Symmetric key for the pre-shared authentication key shared with an RS
     */
    static byte[] key128Rs = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'A', 'u', 't', 'h', 'K', 14, 15, 16};

    /**
     * Symmetric key for the psk shared with an RS. It can be used to protect the tokens issued by the AS.
     */
    static byte[] key256 = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'K', 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};

    /**
     * Asymmetric key of an RS. The AS should know only the public key
     */
    static String asymKeyRs = "piJYILr/9Frrqur4bAz152+6hfzIG6v/dHMG+SK7XaC2JcEvI1ghAKryvKM6og3sNzRQk/nNqzeAfZsIGAYisZbRsPCE3s5BAyYBAiFYIIrXSWPfcBGeHZvB0La2Z0/nCciMirhJb8fv8HcOCyJzIAE=";

    /**
     * Asymmetric key of a client.
     */
    static String asymKeyC = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";

    private static CoapDBConnector db = null;
    private static DtlsAS as = null;
    //private static KissPDP pdp = null;
    private static UcsHelper pdp = null;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        OneKey aKeyRs = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(asymKeyRs)));
        OneKey aKeyC = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(asymKeyC)));

        // pre-shared key between AS and RS. It is used to protect tokens. In this test, all the RSs have the same key.
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256));
        OneKey tokenPsk = new OneKey(keyData);

        // pre-shared authentication key for an RS. In this test, all the RSs have the same key.
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128Rs));
        OneKey authPskRs = new OneKey(keyData);

        // pre-shared key between AS and the client.
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128Client));
        OneKey authPskClient = new OneKey(keyData);

        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;

        // rs1
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("co2");
        scopes.add("r_helloWorld");
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPskRs, tokenPsk, aKeyRs);

        // rs2
        scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("rw_light");
        scopes.add("failTokenType");
        auds.clear();
        auds.add("aud2");
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPskRs, tokenPsk, null);
        
        auds.clear();
        auds.add("actuators");
        db.addRS("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w",
        		 profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPskRs, tokenPsk, aKeyRs);

        //clientA (psk profile)
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("clientA", profiles, null, null, keyTypes, authPskClient, null);

        // ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w (rpk profile)
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", profiles, null, null, keyTypes, null, aKeyC);

        // clientB (psk profile)
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("clientB", profiles, null, null, keyTypes, authPskClient, null);


        KissTime time = new KissTime();
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Peers(cti, "clientA", new HashSet<String>(){{add("actuators");}});

        cti = Base64.getEncoder().encodeToString(new byte[]{0x01});
        claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("aud1"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Peers(cti, "clientA", new HashSet<String>(){{add("aud1");}});


        // AS asymmetric key
        OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);

        //pdp = new KissPDP(db);
        //boolean pdpHandlesRevocations = false;
        pdp = new UcsHelper(db);
        boolean pdpHandlesRevocations = true;

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
        pdp.addAccess("clientA", "rs1", "w_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        pdp.addAccess("clientA", "rs1", "r_helloWorld"); //added
        pdp.addAccess("clientA", "rs2", "r_temp");
        pdp.addAccess("clientA", "rs2", "rw_config");
        pdp.addAccess("clientA", "rs2", "rw_light");
        pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");

        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "r_temp");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "w_temp");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "rw_config");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs1", "r_helloWorld"); //added
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs2", "r_temp");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs2", "rw_config");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs2", "rw_light");
        pdp.addAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", "rs5", "failTokenNotImplemented");
        
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "co2");
        pdp.addAccess("clientB", "rs2", "rw_light");
        pdp.addAccess("clientB", "rs2", "rw_config");
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
        pdp.addAccess("clientD", "rs2", "rw_light");
        pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");        

        pdp.addAccess("clientE", "rs3", "rw_valve");
        pdp.addAccess("clientE", "rs3", "r_pressure");
        pdp.addAccess("clientE", "rs3", "failTokenType");
        pdp.addAccess("clientE", "rs3", "failProfile");

        //dummy test for SQL statements on the trl table.
        db.addRevokedToken("qwertyuiop", "clientA", new HashSet<String>(){{add("rs1");}});
        db.addRevokedToken("asdfghjkl", "clientB", new HashSet<String>(){{add("rs1");}});
        db.addRevokedToken("zxcvbnm", "clientA", new HashSet<String>(){{add("rs2");}});
        db.addRevokedToken("mnbvcxz", "ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", new HashSet<String>(){{add("rs1");}});

        db.addCti2TokenHash("qwertyuiop", "tokenHash_qwertyuiop");
        db.addCti2TokenHash("asdfghjkl", "tokenHash_asdfghjkl");
        db.addCti2TokenHash("zxcvbnm", "tokenHash_zxcvbnm");
        db.addCti2TokenHash("mnbvcxz", "tokenHash_mnbvcxz");

        TrlConfig trlConfig = new TrlConfig("trl", 3, null, true);

        as = new DtlsAS("AS", db, pdp, pdpHandlesRevocations, time, asymmKey,
                "token", "introspect", trlConfig,
                CoAP.DEFAULT_COAP_SECURE_PORT, null, false);
        as.start();
        System.out.println("Server starting");
        //stop();
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        as.stop();
        pdp.close();
        DBHelper.tearDownDB();
        System.out.println("Server stopped");
    }
    
}
