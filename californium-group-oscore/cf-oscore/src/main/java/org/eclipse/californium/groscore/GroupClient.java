/*******************************************************************************
 * Copyright (c) 2020 Bosch Software Innovations GmbH and others.
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
 *    Rikard Höglund (RISE SICS) - Group OSCORE sender functionality
 ******************************************************************************/
package org.eclipse.californium.groscore;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.groscore.group.GroupCtx;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Test sender configured to support multicast requests.
 */
public class GroupClient {

	/**
	 * Destination address to send to
	 */
	// static InetAddress destinationIP = new InetSocketAddress("127.0.0.1",
	// 0).getAddress();
	static InetAddress destinationIP;

	/**
	 * Port to send to.
	 */
	// private static int destinationPort = CoAP.DEFAULT_COAP_PORT;
	private static int destinationPort;

	/**
	 * Resource to perform request against.
	 */
	// static final String requestResource = "/helloWorld";
	// static String requestResource = "/oscore/hello/1";
	static String requestResource;

	/**
	 * The method to use for the request.
	 */
	static final CoAP.Code requestMethod = CoAP.Code.GET;

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
	 * Whether to use OSCORE or not. (Case 1)
	 */
	static final boolean useOSCORE = true;

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();

	/* --- OSCORE Security Context information --- */

	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "Posting";

	public static void start(GroupCtx ctx, String hostname, String URIPath, int portNumber) throws Exception {

		destinationIP = new InetSocketAddress(hostname, 0).getAddress();
		destinationPort = portNumber;
		requestResource = URIPath;

		// Wait 1 second before sending
		Thread.sleep(1000);

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (destinationIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + destinationIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + destinationIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		// If OSCORE is being used set the context information
		if (useOSCORE) {

			db.addContext(requestURI, ctx);

		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder().setNetworkConfig(config);

		if (useOSCORE) {
			builder.setCustomCoapStackArgument(db);
		}

		CoapEndpoint endpoint = builder.build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);

		client.setURI(requestURI);

		Request multicastRequest = null;
		if (requestMethod == Code.POST) {
			multicastRequest = Request.newPost();
			multicastRequest.setPayload(requestPayload);
		} else if (requestMethod == Code.GET) {
			multicastRequest = Request.newGet();
		}
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {
			multicastRequest.getOptions().setOscore(Bytes.EMPTY);
			// For pairwise request:
			// multicastRequest.getOptions().setOscore(OptionEncoder.set(true,
			// requestURI, rid1));
		}

		// Print group context info
		GroupOSCORELocal.printGroupCtx(ctx, db);

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Interop sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Using multicast: " + destinationIP.isMulticastAddress());
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
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		/** Case 9: Client sends replay **/
		// senderCtx.setSenderSeq(0);
		// multicastRequest = Request.newPost();
		// multicastRequest.setPayload(requestPayload);
		// multicastRequest.setType(Type.NON);
		// multicastRequest.getOptions().setOscore(Bytes.EMPTY);
		// client.advanced(handler, multicastRequest);
		// while (handler.waitOn(HANDLER_TIMEOUT)) {
		// // Wait for responses
		// }
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

			// System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}
}
