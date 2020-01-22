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
package se.sics.prototype.apps;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;

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
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Test sender configured to support multicast requests.
 */
public class GroupOscoreClient {
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
//
//	/**
//	 * Multicast address to send to (use the first line to set a custom one).
//	 */
//	//static final InetAddress multicastIP = new InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
//	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT - 1000;

	/**
	 * Resource to perform request against.
	 */
	static final String requestResource  = "/toggle";
	
	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "on";
	
	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	
	/**
	 * Indicate if the basic UI for the client should be enabled
	 */
	//static final boolean ui = true;
	
	/**
	 * OSCORE Security Context database (sender)
	 */
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	
	public static void start(GroupOSCoreCtx derivedCtx, InetAddress multicastIP) throws Exception {
		/**
		 * URI to perform request against. Need to check for IPv6 to surround it with []
		 */
		String requestURI;
		if(multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

		//Install cryptographic providers
		InstallCryptoProviders.installProvider();
		//InstallCryptoProviders.generateCounterSignKey(); //For generating keys
		
		//If OSCORE is being used set the context information
		GroupOSCoreCtx ctx = null;
		if(useOSCORE) {
			ctx = derivedCtx;
			ctx.REPLAY_CHECK = true; //Enable replay checks
			db.addContext(requestURI, ctx);

//			if(CoapEndpoint.isDefaultCoapStackFactorySet() == false) {
//				OSCoreCoapStackFactory.useAsDefault();
//			}
		}
		
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);	
		client.setURI(requestURI);

		//Information about the sender
		System.out.println("==================");
		System.out.println("*Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		//System.out.println("Request method: " + multicastRequest.getCode());
		System.out.println("Request payload: " + requestPayload);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		
		System.out.print("*");
		Utility.printContextInfo(ctx);
		System.out.println("==================");
		
		System.out.println("");
		System.out.println("Ready to send requests to the OSCORE group.");
		
		//Send messages to trigger the LEDs/solenoids on/off
		//int count = 10;
		//String payload = requestPayload;
		
		Scanner scanner = new Scanner(System.in);
		String command = "";
		
		while(!command.equals("q")) {
			
			System.out.println("Enter command: ");
			command = scanner.next();
			
			Request multicastRequest = Request.newPost();
			multicastRequest.setPayload(command);
			multicastRequest.setType(Type.NON);
			if(useOSCORE) {
				multicastRequest.getOptions().setOscore(new byte[0]); //Set the OSCORE option
			}
			
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

			Thread.sleep(1000);
//			count--;
//			if(payload.equals("on")) {
//				payload = "off";
//			} else {
//				payload = "on";
//			}
			
		}
		
		scanner.close();
		
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
