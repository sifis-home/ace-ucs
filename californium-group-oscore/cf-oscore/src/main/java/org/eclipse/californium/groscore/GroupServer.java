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
 *    Rikard Höglund (RISE SICS) - Group OSCORE receiver functionality
 ******************************************************************************/
package org.eclipse.californium.groscore;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.groscore.group.GroupCtx;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupServer {

	/**
	 * Controls whether or not the receiver will reply to incoming multicast
	 * non-confirmable requests.
	 * 
	 * The receiver will always reply to confirmable requests (can be used with
	 * unicast).
	 * 
	 */
	static final boolean replyToNonConfirmable = true;

	/**
	 * Whether to use OSCORE or not. (Case 1)
	 */
	static final boolean useOSCORE = true;

	/**
	 * Give the receiver a random unicast IP (from the loopback 127.0.0.0/8
	 * range) FIXME: Communication does not work with this turned on
	 */
	static final boolean randomUnicastIP = false;

	/**
	 * Multicast address to listen to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static final InetAddress listenIP = CoAP.MULTICAST_IPV4;
	static final InetAddress listenIP = new InetSocketAddress("0.0.0.0", 0).getAddress();

	/**
	 * Build endpoint to listen on multicast IP.
	 */
	static final boolean useMulticast = listenIP.isMulticastAddress();

	/* --- OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";

	/* --- OSCORE Security Context information --- */

	private static Random random;

	/**
	 * Port to listen to.
	 */
	static int listenPort;

	public static void start(GroupCtx ctx, int port) throws Exception {

		listenPort = port;
		
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		// If OSCORE is being used set the context information
		if (useOSCORE) {

			db.addContext(uriLocal, ctx);

		}

		// Initialize random number generator
		random = new Random();

		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config);


		CoapServer server = new CoapServer(config);
		server.addEndpoint(endpoint);
		server.add(new OtherOscoreResource());

		// Build resource hierarchy
		CoapResource oscore = new CoapResource("oscore", true);
		CoapResource oscore_hello = new CoapResource("hello", true);

		oscore_hello.add(new CoapHelloWorldResource());
		oscore_hello.add(new OscoreHelloWorldResource());

		oscore.add(oscore_hello);
		server.add(oscore);

		// Print group context info
		GroupOSCORELocal.printGroupCtx(ctx, db);

		// Information about the receiver
		System.out.println("==================");
		System.out.println("*Interop receiver");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to IP: " + listenIP.getHostAddress());
		System.out.println("Using multicast: " + useMulticast);
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + endpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("==================");

		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {

		InetSocketAddress localAddress;
		// Set a random loopback address in 127.0.0.0/8
		if (randomUnicastIP) {
			byte[] b = new byte[4];
			random.nextBytes(b);
			b[0] = 127;
			b[1] = 0;
			InetAddress inetAdd = InetAddress.getByAddress(b);

			localAddress = new InetSocketAddress(inetAdd, listenPort);
		} else { // Set the wildcard address (0.0.0.0)
			localAddress = new InetSocketAddress(listenPort);
		}

		Connector connector = null;
		if (useMulticast) {
			connector = new UdpMulticastConnector(localAddress, listenIP);
		} else {
			InetSocketAddress unicastAddress = new InetSocketAddress(listenIP, listenPort);
			connector = new UDPConnector(unicastAddress);
		}

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector);

		if (useOSCORE) {
			builder.setCustomCoapStackArgument(db);
		}

		return builder.build();
	}

	private static class CoapHelloWorldResource extends CoapResource {

		private CoapHelloWorldResource() {
			// set resource identifier
			super("coap");

			// set display name
			getAttributes().setTitle("CoAP Hello-World Resource");

		}

		// Handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, "Hello World!", MediaTypeRegistry.TEXT_PLAIN);
		}
	}
	
	private static class OscoreHelloWorldResource extends OSCoreResource {

		private OscoreHelloWorldResource() {
			// set resource identifier
			super("1", true);

			// set display name
			getAttributes().setTitle("OSCORE Hello-World Resource");

		}

		// Handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, "Hello World!", MediaTypeRegistry.TEXT_PLAIN);
		}
	}

	private static class OtherOscoreResource extends CoapResource {

		private String id;
		private int count = 0;

		private OtherOscoreResource() {
			// set resource identifier
			super("helloWorld"); // Changed

			// set display name
			getAttributes().setTitle("Hello-World Resource");

			id = Integer.toString(random.nextInt(1000));
			// id = Utils.toHexString(sid);

			System.out.println("coap receiver: " + id);
		}

		// Added for handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			handlePOST(exchange);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {

			System.out.println("Receiving request #" + count);
			count++;

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			// respond to the request if confirmable or replies are set to be
			// sent for non-confirmable
			// payload is set to request payload changed to uppercase plus the
			// receiver ID
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				String requestPayload = exchange.getRequestText().toUpperCase();
				if(requestPayload == null || requestPayload.length() == 0) {
					r.setPayload("Response from: " + id);
				} else {
					r.setPayload(requestPayload.toUpperCase() + ". Response from: " + id);
				}

				if (isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}

				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(r));

				exchange.respond(r);
			}

		}

	}
}
