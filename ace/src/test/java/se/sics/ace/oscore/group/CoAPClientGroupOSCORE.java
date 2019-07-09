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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
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
     
    	//Perform token request to AS using PSK
    	//groupOSCOREMultipleRolesCWT();
    	
    	//Perform token request to AS using RPK
    	groupOSCOREMultipleRolesCWT_RPK();
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
    	System.out.println("Using PSK DTLS towards AS");
    	
    	String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("purelistener");
    	
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
        
		CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
		
        CBORObject responseFromAS = CBORObject.DecodeFromBytes(response.getPayload());
        
        
        Map<Short, CBORObject> map = Constants.getParams(responseFromAS);
        
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        System.out.println("Received reply from AS: " + responseFromAS.ToJSONString());
        System.out.println("Access Token: " + map.get(Constants.ACCESS_TOKEN).ToJSONString());
        System.out.println("Cnf: " + map.get(Constants.CNF).ToJSONString());
     }
    
    // M.T.
    /**
     * Request a CoapToken using RPK, for asking access to an
     * OSCORE group with multiple roles, using a CWT.
     * 
     * @throws IOException if communication fails
     * @throws ConnectorException if communication fails
     * @throws AceException if ACE processing fails
     * @throws CoseException 
     * 
     */
    public static void groupOSCOREMultipleRolesCWT_RPK() throws IOException, ConnectorException, AceException, CoseException { 

    	//Rikard: Name that clientF will have getSenderId() in Token when using RPK:
        // ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w

    	String tokenURI = "coaps://" + AS_ADDRESS + ":" + AS_SECURE_PORT + "/token";

    	System.out.println("Performing Token request to AS at " + tokenURI);
    	System.out.println("Using RPK DTLS towards AS");
    	
    	String gid = new String("feedca570000");
    	String role1 = new String("requester");
    	String role2 = new String("purelistener");
    	
    	//RPK connecting code from TestDtlsClient2
    	OneKey key = new OneKey(
                CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));

        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setIdentity(key.AsPrivateKey(), 
                key.AsPublicKey());
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setRpkTrustAll();
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
        
		CoapResponse response = client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                MediaTypeRegistry.APPLICATION_CBOR);    
		
        CBORObject responseFromAS = CBORObject.DecodeFromBytes(response.getPayload());
        
        
        Map<Short, CBORObject> map = Constants.getParams(responseFromAS);
        
        //assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        //assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        System.out.println("Received reply from AS: " + responseFromAS.ToJSONString());
        System.out.println("Access Token: " + map.get(Constants.ACCESS_TOKEN).ToJSONString());
        System.out.println("Cnf: " + map.get(Constants.CNF).ToJSONString());
     }
    
}
