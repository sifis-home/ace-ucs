/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Rikard Höglund (RISE SICS)
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Test sender configured to support multicast requests.
 */
public class GroupOSCORESenderECDSA {
	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MULTICAST_BASE_MID, 65000);
		}

	};

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 2000;
	
	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	//static final InetAddress multicastIP = new InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Resource to perform request against.
	 */
	static final String requestResource  = "/helloWorld";
	
	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "test";
	
	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static AlgorithmID alg = AlgorithmID.AES_GCM_128; //Use GCM for no BouncyCastle
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	
	//Group OSCORE specific values for the countersignature
	private final static AlgorithmID alg_countersign = AlgorithmID.ECDSA_256;
	private final static Integer par_countersign = null;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	
	/* Rikard: Note regarding countersignature keys.
	 * The sid_private_key contains both the public and private keys.
	 * The rid*_public_key contains only the public key.
	 * For information on the keys see the Countersign_Keys file.
	 */
	
	private final static byte[] sid = new byte[] { 0x25 };
	private final static String sid_private_key_string = "pgMmAQIgASFYIErNHsCmkyKsCh0kt16utIujYCK1l0W1fo3NZtfzCdK6Ilgg7n8KnN9SLkbIiheU8uxuQ25LzBwW+K5ed1+Z3qeXdjwjWCDtw3Wqf4uQoY/dYx8bjZUpUuBfC3k1UHxIcIgs8FxOQg==";
	private static OneKey sid_private_key;
	
	private final static byte[] rid1 = new byte[] { 0x52 }; //Recipient 1
	private final static String rid1_public_key_string = "pQMmAQIgASFYICOiiV4tfl1H+lwa09KGLTZmF7vs3MnoDbknAet2KumIIlggI4nnvVDN/VxssAfVor9MDWVHXnG2QzrFqhpId7lCsWU=";
	private static OneKey rid1_public_key;
	
	private final static byte[] rid2 = new byte[] { 0x77 }; //Recipient 2
	private final static String rid2_public_key_string = "pQMmAQIgASFYICDhVZs4x3YIiIGDDkMB3fLwA9KbDiLHUHRC+d9CCoF/IlggkHYXeExSt8/x/oyP4H1lnfMOjN5DeGvoDlXKja4BKGw=";
	private static OneKey rid2_public_key;
	
	private final static byte[] rid0 = new byte[] { (byte) 0xCC }; //Does not exist
	
	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; //Group ID
	/* --- OSCORE Security Context information --- */
	
	public static void main(String args[]) throws Exception {
		
		//Do not install any extra crypto providers
		
		/**
		 * URI to perform request against. Need to check for IPv6 to surround it with []
		 */
		String requestURI;
		if(multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

		//Add private & public keys for sender & receiver(s)
		sid_private_key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));
		rid1_public_key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rid1_public_key_string)));
		rid2_public_key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rid2_public_key_string)));
		
		//If OSCORE is being used set the context information
		if(useOSCORE) {
			GroupOSCoreCtx ctx = new GroupOSCoreCtx(master_secret, true, alg, sid, kdf, 32, 
					master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
			ctx.setOptimizedResponse(true); // Enable optimized responses
			ctx.addRecipientContext(rid0);
			ctx.addRecipientContext(rid1, rid1_public_key);
			ctx.addRecipientContext(rid2, rid2_public_key);
			db.addContext(requestURI, ctx);

			OSCoreCoapStackFactory.useAsDefault();
		}
		
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);
		
		client.setURI(requestURI);
		Request multicastRequest = Request.newPost();
		multicastRequest.setPayload(requestPayload);
		multicastRequest.setType(Type.NON);
		if(useOSCORE) {
			multicastRequest.getOptions().setOscore(new byte[0]); //Set the OSCORE option
		}

		//Information about the sender
		System.out.println("==================");
		System.out.println("*Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Request method: " + multicastRequest.getCode());
		System.out.println("Request payload: " + requestPayload);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		System.out.println("==================");
		
		try {
			String host = new URI(client.getURI()).getHost();
			int port = new URI(client.getURI()).getPort();
			System.out.println("Sending to: " + host + ":" + port);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}
		System.out.println("Sending from: " + client.getEndpoint().getAddress());
		System.out.println(Utils.prettyPrint(multicastRequest));

		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT));

	}

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		/**
		 * Handle and parse incoming responses.
		 */
		@Override
		public void onLoad(CoapResponse response) {
			on();
			
			//System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};
}
