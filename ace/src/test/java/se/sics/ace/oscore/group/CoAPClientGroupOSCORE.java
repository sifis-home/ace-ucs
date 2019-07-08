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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.elements.exception.ConnectorException;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;

/**
 * A client requesting a Token from the AS to post to
 * an RS acting as Group OSCORE Group Manager.
 * 
 * This should be run with as CoapASTestServerGroupOSCORE server.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class CoAPClientGroupOSCORE {

	//Sets the secure port to use
	private final static int AS_SECURE_PORT = CoAP.DEFAULT_COAP_SECURE_PORT;
	//Set the hostname/IP of the AS
	private final static String AS_ADDRESS = "localhost";

    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    
    public static void main(String[] args) throws Exception {
    	
    	//Install needed cryptography providers
    	org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
     
    	//Perform token request to AS
    	groupOSCOREMultipleRolesCWT();
    }
    
    // M.T.
    /**
     * Request a CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a CWT.
     * 
     * @throws IOException if communication fails
     * @throws ConnectorException if communication fails
     * @throws AceException if ACE processing fails
     * 
     */
    public static void groupOSCOREMultipleRolesCWT() throws IOException, ConnectorException, AceException { 

    	String tokenURI = "coaps://" + AS_ADDRESS + ":" + AS_SECURE_PORT + "/token";

    	System.out.println("Performing Token request to AS at " + tokenURI);

    	String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	String role1 = new String("requester");
    	String role2 = new String("purelistener");
    	String role3 = new String("listener");
    	
    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("clientF", key128));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setNetworkConfig(NetworkConfig.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(tokenURI);
        client.setEndpoint(e);
        dtlsConnector.start();
    	
    	
        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
    	
        // Both requested roles are allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(gid);
    	CBORObject cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
		@SuppressWarnings("unused")
		CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
        //CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
//        Map<Short, CBORObject> map = Constants.getParams(res);
        
        //assert(map.containsKey(Constants.ACCESS_TOKEN));
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(map.containsKey(Constants.CNF));
        //assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid2);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role2);
    	cborArrayScope.Add(cborArrayRoles);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        
//        res = CBORObject.DecodeFromBytes(response.getPayload());
        
//        map = Constants.getParams(res);
        
        //assert(map.size() == 1);
        //assert(map.containsKey(Constants.ERROR));
        //assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role1);
    	cborArrayRoles.Add(role3);
    	cborArrayScope.Add(cborArrayRoles);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        
//        res = CBORObject.DecodeFromBytes(response.getPayload());
        
//        map = Constants.getParams(res);
        
        //assert(map.containsKey(Constants.ACCESS_TOKEN));
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(map.containsKey(Constants.CNF));
        //assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        //assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
//        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
//        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        //assert(receivedArrayScope.getType().equals(CBORType.Array));
        //assert(receivedArrayScope.size() == 2);
        
        cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role1);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	//Assert.assertArrayEquals(receivedScope, byteStringScope);
    	
    	
    	// Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayRoles = CBORObject.NewArray();
    	cborArrayRoles.Add(role2);
    	cborArrayRoles.Add(role3);
    	cborArrayScope.Add(cborArrayRoles);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, 
                CBORObject.FromObject(byteStringScope));
        
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        
        response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);
        
        CBORObject responseFromAS = CBORObject.DecodeFromBytes(response.getPayload());
//        res = CBORObject.DecodeFromBytes(response.getPayload());
        
//        map = Constants.getParams(res);
        
        //assert(map.containsKey(Constants.ACCESS_TOKEN));
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(map.containsKey(Constants.CNF));
        //assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        //assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
//        receivedScope = map.get(Constants.SCOPE).GetByteString();
//        receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        //assert(receivedArrayScope.getType().equals(CBORType.Array));
        //assert(receivedArrayScope.size() == 2);
        //Assert.assertEquals(1,2);
        
        cborArrayScope = CBORObject.NewArray();
    	cborArrayScope.Add(gid);
    	cborArrayScope.Add(role2);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	//Assert.assertArrayEquals(receivedScope, byteStringScope);

    	System.out.println("Received reply from AS: " + responseFromAS.ToJSONString());
    }
    
//    // M.T.
//    /**
//     * Request a CoapToken using PSK, for asking access to an
//     * OSCORE group with multiple roles, using a CWT.
//     * (Alternative version with different client)
//     * 
//     * @throws Exception
//     */
//    public static void groupOSCOREAltClientCWT() throws Exception { 
//        
//    	String gid = new String("feedca570000");
//    	String role1 = new String("requester");
//    	String role2 = new String("purelistener");
//    	String role3 = new String("listener");
//    	
//    	DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
//        builder.setAddress(new InetSocketAddress(0));
//        builder.setPskStore(new StaticPskStore("clientG", key128));
//        builder.setSupportedCipherSuites(new CipherSuite[]{
//                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
//        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
//        Builder ceb = new Builder();
//        ceb.setConnector(dtlsConnector);
//        ceb.setNetworkConfig(NetworkConfig.getStandard());
//        CoapEndpoint e = ceb.build();
//        CoapClient client = new CoapClient(tokenURI);
//        client.setEndpoint(e);
//        dtlsConnector.start();
//    	
//    	
//        // The scope is a CBOR Array encoded as a CBOR byte string, as in draft-ietf-ace-key-groupcomm
//    	
//        // None of the requested ones is allowed in the specified group
//        Map<Short, CBORObject> params = new HashMap<>(); 
//        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
//        
//        CBORObject cborArrayScope = CBORObject.NewArray();
//    	cborArrayScope.Add(gid);
//    	CBORObject cborArrayRoles = CBORObject.NewArray();
//    	cborArrayRoles.Add(role2);
//    	cborArrayRoles.Add(role3);
//    	cborArrayScope.Add(cborArrayRoles);
//    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
//        
//        params.put(Constants.SCOPE, 
//                CBORObject.FromObject(byteStringScope));
//        
//        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
//        
//        CoapResponse response = client.post(
//                Constants.getCBOR(params).EncodeToBytes(), 
//                MediaTypeRegistry.APPLICATION_CBOR);    
//        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
//        
//        Map<Short, CBORObject> map = Constants.getParams(res);
//        
//        //assert(map.size() == 1);
//        //assert(map.containsKey(Constants.ERROR));
//        //assert(map.get(Constants.ERROR).AsInt16() == Constants.INVALID_SCOPE);
//        
//
//        // Only one role out of the two requested ones is allowed in the specified group
//        params = new HashMap<>();
//        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
//        
//        cborArrayScope = CBORObject.NewArray();
//        cborArrayScope.Add(gid);
//    	cborArrayRoles = CBORObject.NewArray();
//    	cborArrayRoles.Add(role1);
//    	cborArrayRoles.Add(role2);
//    	cborArrayScope.Add(cborArrayRoles);
//    	byteStringScope = cborArrayScope.EncodeToBytes();
//    	
//    	
//        params.put(Constants.SCOPE, 
//                CBORObject.FromObject(byteStringScope));
//        
//        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
//        
//        response = client.post(
//                Constants.getCBOR(params).EncodeToBytes(), 
//                MediaTypeRegistry.APPLICATION_CBOR);    
//        res = CBORObject.DecodeFromBytes(response.getPayload());
//        
//        map = Constants.getParams(res);
//        
//        //assert(map.containsKey(Constants.ACCESS_TOKEN));
//        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
//        //assert(map.containsKey(Constants.CNF));
//        //assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
//        //assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
//        
//        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
//        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
//        //assert(receivedArrayScope.getType().equals(CBORType.Array));
//        //assert(receivedArrayScope.size() == 2);
//        
//        cborArrayScope = CBORObject.NewArray();
//    	cborArrayScope.Add(gid);
//    	cborArrayScope.Add(role1);
//    	byteStringScope = cborArrayScope.EncodeToBytes();
//    	//Assert.assertArrayEquals(receivedScope, byteStringScope);
//        
//    }

}
