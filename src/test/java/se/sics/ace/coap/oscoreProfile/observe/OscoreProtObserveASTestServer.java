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
package se.sics.ace.coap.oscoreProfile.observe;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.CoAP;
import org.junit.Assert;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.RevocationHandler;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.OscoreAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.ucs.UcsHelper;

import java.util.*;

/**
 * Authorization Server to test with OscoreProtObserveCTestClient
 *
 * @author Marco Rasori
 *
 *
 */
public class OscoreProtObserveASTestServer
{
    static byte[] key128rs = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * Symmetric key for the psk shared with the client
     */
    static byte[] key128c = {'C', '-', 'A', 'S', ' ', 'P', 'S', 'K', 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * Symmetric key for the psk shared with an RS. It can be used to protect the tokens issued by the AS.
     */
    static byte[] key256rs = {'R', 'S', '-', 'A', 'S', ' ', 'P', 'S', 'K', 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};

    private static CoapDBConnector db = null;
    private static OscoreAS as = null;
    //private static KissPDP pdp = null;
    private static UcsHelper pdp = null;

    // The map has as key the name of a Client or Resource Server,
    // and as value the OSCORE identity of that peer with the AS.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> peerNamesToIdentities = new HashMap<>();
    
    
    // The map has as key the OSCORE identity of the Client or Resource Server,
    // and as value the name of that peer with the AS.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> peerIdentitiesToNames = new HashMap<>();
    
    
    // The inner map has as key the name of a Client or Resource Server, and
    // as value the OSCORE identity that this specific AS has with that peer.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> myIdentities = new HashMap<>();
  
    // OSCORE Context ID used to communicate with Clients and Resource Server (it can be null)
    private static byte[] idContext = new byte[] {0x44};
    
    /**
     * The OSCORE AS for testing, autostarted by tests needing this.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        //key 256 (to protect access tokens)
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256rs));
        OneKey tokenPskRs = new OneKey(keyData);

        //key 128 (shared with the rs)
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128rs));
        OneKey authPskRs = new OneKey(keyData);

        //key 128 (shared with the client)
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128c));
        OneKey authPskC = new OneKey(keyData);
        
        String myName = "AS";
        String myIdentity = buildOscoreIdentity(new byte[] {0x33}, idContext);
        String peerIdentity;
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("actuators");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        //long expiration = 30000L;
        long expiration = 30000L; // changed to test token expiration
                                  // FIXME: is in milliseconds, wrong in Constants which says it is in seconds.)

        // rs1
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("co2");
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPskRs, tokenPskRs, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x11}, idContext);
        peerNamesToIdentities.put("rs1", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "rs1");
        myIdentities.put("rs1", myIdentity);

        // rs2
        scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("rw_light");
        scopes.add("failTokenType");
        auds.clear();
        auds.add("aud2");
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPskRs, tokenPskRs, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x12}, idContext);
        peerNamesToIdentities.put("rs2", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "rs2");
        myIdentities.put("rs2", myIdentity);
        

        // clientA
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, keyTypes, authPskC, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x22}, idContext);
        peerNamesToIdentities.put("clientA", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "clientA");
        myIdentities.put("clientA", myIdentity);

        // clientB
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("clientB", profiles, null, null, keyTypes, authPskC, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x24}, idContext);
        peerNamesToIdentities.put("clientB", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "clientB");
        myIdentities.put("clientB", myIdentity);
        
        KissTime time = new KissTime();
        
        // Add a Token to successfully test introspection
        //
        // Note that this Token is not including everything expected in a Token
        // for the OSCORE profile, especially the 'cnf' claim requiring specific
        // preparation in the /token endpoint
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);
        db.addCti2Peers(cti, "clientA", new HashSet<String>(){{add("actuators");}});


        OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        //pdp = new KissPDP(db);
        //boolean phpHandlesRevocations = false;
        pdp = new UcsHelper(db);
        boolean phpHandlesRevocations = true;
        
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
        pdp.addAccess("clientA", "rs1", "r_helloWorld");
        pdp.addAccess("clientA", "rs2", "r_temp");
        pdp.addAccess("clientA", "rs2", "rw_config");
        pdp.addAccess("clientA", "rs2", "rw_light");
        pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");

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

//        pdp.revokeAccess("clientA", "rs1", "r_temp");

        //dummy test for SQL statements on the trl table.
        db.addRevokedToken("qwertyuiop", "clientA", new HashSet<String>(){{add("rs1");}});
        db.addRevokedToken("asdfghjkl", "clientB", new HashSet<String>(){{add("rs1");}});
        db.addRevokedToken("zxcvbnm", "clientA", new HashSet<String>(){{add("rs2");}});

        db.addCti2TokenHash("qwertyuiop", "tokenHash_qwertyuiop");
        db.addCti2TokenHash("asdfghjkl", "tokenHash_asdfghjkl");
        db.addCti2TokenHash("zxcvbnm", "tokenHash_zxcvbnm");


        as = new OscoreAS(myName, db, pdp, phpHandlesRevocations, time, asymmKey,"token", "introspect", "trl", true,
                          CoAP.DEFAULT_COAP_PORT, null, false, (short)1, true,
                          peerNamesToIdentities, peerIdentitiesToNames, myIdentities);
        
        as.start();
        System.out.println("Server starting");
        //as.stop();
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
    
    private static String buildOscoreIdentity(byte[] senderId, byte[] contextId) {
    	
    	if (senderId == null)
    		return null;
    	
    	String identity = "";
    	
    	if (contextId != null) {
    		identity += Base64.getEncoder().encodeToString(contextId);
    		identity += ":";
    	}
    	
    	identity += Base64.getEncoder().encodeToString(senderId);
    	
    	return identity;
    	
    }
    
}