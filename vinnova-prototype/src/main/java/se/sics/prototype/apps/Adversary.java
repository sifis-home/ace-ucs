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
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Test sender configured to support multicast requests.
 */
public class Adversary {
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
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT - 1000;
	
	/**
	 * Replay message for the adversary to send
	 */
	static byte[] replayMessageBytes_groupA = new byte[] {
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x35, (byte) 0x84, (byte) 0xb6, (byte) 0x83, (byte) 0x44,
			(byte) 0x3b, (byte) 0xad, (byte) 0x34, (byte) 0x95, (byte) 0x9a, (byte) 0x19, (byte) 0x01, (byte) 0x06,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x11, (byte) 0xff,
			(byte) 0x29, (byte) 0x18, (byte) 0x2a, (byte) 0xc3, (byte) 0x35, (byte) 0x61, (byte) 0x7d, (byte) 0x68,
			(byte) 0xfa, (byte) 0xf2, (byte) 0x0e, (byte) 0xf4, (byte) 0xdb, (byte) 0x19, (byte) 0x75, (byte) 0xc4,
			(byte) 0xea, (byte) 0xc2, (byte) 0x57, (byte) 0xa1, (byte) 0x74, (byte) 0x33, (byte) 0x21, (byte) 0x75,
			(byte) 0xe9, (byte) 0x12, (byte) 0x07, (byte) 0x8d, (byte) 0x7f, (byte) 0xc4, (byte) 0xa3, (byte) 0xa2,
			(byte) 0xea, (byte) 0x5b, (byte) 0x85, (byte) 0x0c, (byte) 0xdb, (byte) 0x5f, (byte) 0x41, (byte) 0x45,
			(byte) 0x26, (byte) 0xf4, (byte) 0x90, (byte) 0xba, (byte) 0x88, (byte) 0xf4, (byte) 0x90, (byte) 0xfd,
			(byte) 0xce, (byte) 0x36, (byte) 0xdc, (byte) 0xe2, (byte) 0x17, (byte) 0x8f, (byte) 0x4a, (byte) 0x8f,
			(byte) 0x8d, (byte) 0x90, (byte) 0x27, (byte) 0xbc, (byte) 0x2d, (byte) 0xa5, (byte) 0x2c, (byte) 0x8e,
			(byte) 0x7d, (byte) 0x83, (byte) 0x76, (byte) 0x6d, (byte) 0xdd, (byte) 0x3b, (byte) 0xe9, (byte) 0xab,
			(byte) 0x91, (byte) 0x6e, (byte) 0xc3, (byte) 0xb2, (byte) 0x89, (byte) 0xca, (byte) 0xeb, (byte) 0x00,
			(byte) 0xed, (byte) 0xa4, (byte) 0x0f
	};
	static byte[] replayMessageBytes_groupB = new byte[] { 
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x2b, (byte) 0x74, (byte) 0x3b, (byte) 0x19, (byte) 0xca,
			(byte) 0x7e, (byte) 0xb6, (byte) 0xe6, (byte) 0x70, (byte) 0x9a, (byte) 0x19, (byte) 0x01, (byte) 0x06,
			(byte) 0xbb, (byte) 0xbb, (byte) 0xbb, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x22, (byte) 0xff,
			(byte) 0x8b, (byte) 0x84, (byte) 0xaf, (byte) 0xcb, (byte) 0xa1, (byte) 0x4b, (byte) 0xe5, (byte) 0xcb,
			(byte) 0x03, (byte) 0x52, (byte) 0x10, (byte) 0x01, (byte) 0xec, (byte) 0xb2, (byte) 0x31, (byte) 0x9b,
			(byte) 0xe5, (byte) 0xaf, (byte) 0xec, (byte) 0x75, (byte) 0x53, (byte) 0x12, (byte) 0xbb, (byte) 0x6b,
			(byte) 0x98, (byte) 0xce, (byte) 0xb4, (byte) 0x76, (byte) 0xb6, (byte) 0xdb, (byte) 0x59, (byte) 0x71,
			(byte) 0xcc, (byte) 0x73, (byte) 0x87, (byte) 0x33, (byte) 0x75, (byte) 0xcd, (byte) 0x7b, (byte) 0xb0,
			(byte) 0x58, (byte) 0xcd, (byte) 0x97, (byte) 0x2e, (byte) 0xe0, (byte) 0x6a, (byte) 0x1e, (byte) 0x83,
			(byte) 0x26, (byte) 0x6e, (byte) 0x5f, (byte) 0x68, (byte) 0x47, (byte) 0x49, (byte) 0xb6, (byte) 0x25,
			(byte) 0xf7, (byte) 0x7c, (byte) 0x78, (byte) 0x50, (byte) 0x3d, (byte) 0xd8, (byte) 0xc1, (byte) 0x56,
			(byte) 0xee, (byte) 0xb3, (byte) 0x93, (byte) 0x96, (byte) 0x37, (byte) 0xce, (byte) 0x5f, (byte) 0xea,
			(byte) 0xb7, (byte) 0x76, (byte) 0x9c, (byte) 0x31, (byte) 0x24, (byte) 0x24, (byte) 0xf6, (byte) 0x95,
			(byte) 0x30, (byte) 0x57, (byte) 0x74, (byte) 0xac, (byte) 0xc9, (byte) 0x09
	};
	
	/**
	 * Message where the ciphertext and Partial IV were modified
	 */
	static byte[] ciphertextModifiedMessageBytes_groupA = new byte[] {
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x35, (byte) 0x84, (byte) 0xb6, (byte) 0x83, (byte) 0x44,
			(byte) 0x3b, (byte) 0xad, (byte) 0x34, (byte) 0x95, (byte) 0x9a, (byte) 0x19, (byte) 0xFF, (byte) 0x06,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x11, (byte) 0xff,
			(byte) 0x29, (byte) 0x18, (byte) 0x2a, (byte) 0xb3, (byte) 0x35, (byte) 0x61, (byte) 0x7d, (byte) 0x68,
			(byte) 0xfa, (byte) 0xf2, (byte) 0x0e, (byte) 0xf4, (byte) 0xdb, (byte) 0x19, (byte) 0x75, (byte) 0xc4,
			(byte) 0xea, (byte) 0xc2, (byte) 0x57, (byte) 0xa1, (byte) 0x74, (byte) 0x33, (byte) 0x21, (byte) 0x75,
			(byte) 0xe9, (byte) 0x12, (byte) 0x07, (byte) 0x8d, (byte) 0x7f, (byte) 0xc4, (byte) 0xa3, (byte) 0xa2,
			(byte) 0xea, (byte) 0x5b, (byte) 0x85, (byte) 0x0c, (byte) 0xdb, (byte) 0x5f, (byte) 0x41, (byte) 0x45,
			(byte) 0x26, (byte) 0xf4, (byte) 0x90, (byte) 0xba, (byte) 0x88, (byte) 0xf4, (byte) 0x90, (byte) 0xfd,
			(byte) 0xce, (byte) 0x36, (byte) 0xdc, (byte) 0xe2, (byte) 0x17, (byte) 0x8f, (byte) 0x4a, (byte) 0x8f,
			(byte) 0x8d, (byte) 0x90, (byte) 0x27, (byte) 0xbc, (byte) 0x2d, (byte) 0xa5, (byte) 0x2c, (byte) 0x8e,
			(byte) 0x7d, (byte) 0x83, (byte) 0x76, (byte) 0x6d, (byte) 0xdd, (byte) 0x3b, (byte) 0xe9, (byte) 0xab,
			(byte) 0x91, (byte) 0x6e, (byte) 0xc3, (byte) 0xb2, (byte) 0x89, (byte) 0xca, (byte) 0xeb, (byte) 0x00,
			(byte) 0xed, (byte) 0xa4, (byte) 0x0f
	};
	static byte[] ciphertextModifiedMessageBytes_groupB = new byte[] { 
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x2b, (byte) 0x74, (byte) 0x3b, (byte) 0x19, (byte) 0xca,
			(byte) 0x7e, (byte) 0xb6, (byte) 0xe6, (byte) 0x70, (byte) 0x9a, (byte) 0x19, (byte) 0xFF, (byte) 0x06,
			(byte) 0xbb, (byte) 0xbb, (byte) 0xbb, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x22, (byte) 0xff,
			(byte) 0x8b, (byte) 0x84, (byte) 0xaf, (byte) 0xbb, (byte) 0xa1, (byte) 0x4b, (byte) 0xe5, (byte) 0xcb,
			(byte) 0x03, (byte) 0x52, (byte) 0x10, (byte) 0x01, (byte) 0xec, (byte) 0xb2, (byte) 0x31, (byte) 0x9b,
			(byte) 0xe5, (byte) 0xaf, (byte) 0xec, (byte) 0x75, (byte) 0x53, (byte) 0x12, (byte) 0xbb, (byte) 0x6b,
			(byte) 0x98, (byte) 0xce, (byte) 0xb4, (byte) 0x76, (byte) 0xb6, (byte) 0xdb, (byte) 0x59, (byte) 0x71,
			(byte) 0xcc, (byte) 0x73, (byte) 0x87, (byte) 0x33, (byte) 0x75, (byte) 0xcd, (byte) 0x7b, (byte) 0xb0,
			(byte) 0x58, (byte) 0xcd, (byte) 0x97, (byte) 0x2e, (byte) 0xe0, (byte) 0x6a, (byte) 0x1e, (byte) 0x83,
			(byte) 0x26, (byte) 0x6e, (byte) 0x5f, (byte) 0x68, (byte) 0x47, (byte) 0x49, (byte) 0xb6, (byte) 0x25,
			(byte) 0xf7, (byte) 0x7c, (byte) 0x78, (byte) 0x50, (byte) 0x3d, (byte) 0xd8, (byte) 0xc1, (byte) 0x56,
			(byte) 0xee, (byte) 0xb3, (byte) 0x93, (byte) 0x96, (byte) 0x37, (byte) 0xce, (byte) 0x5f, (byte) 0xea,
			(byte) 0xb7, (byte) 0x76, (byte) 0x9c, (byte) 0x31, (byte) 0x24, (byte) 0x24, (byte) 0xf6, (byte) 0x95,
			(byte) 0x30, (byte) 0x57, (byte) 0x74, (byte) 0xac, (byte) 0xc9, (byte) 0x09
	};
	
	/**
	 * Message where the signature and Partial IV were modified
	 */
	static byte[] signatureModifiedMessageBytes_groupA = new byte[] {
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x35, (byte) 0x84, (byte) 0xb6, (byte) 0x83, (byte) 0x44,
			(byte) 0x3b, (byte) 0xad, (byte) 0x34, (byte) 0x95, (byte) 0x9a, (byte) 0x19, (byte) 0xFF, (byte) 0x06,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x11, (byte) 0xff,
			(byte) 0x29, (byte) 0x18, (byte) 0x2a, (byte) 0xc3, (byte) 0x35, (byte) 0x61, (byte) 0x7d, (byte) 0x68,
			(byte) 0xfa, (byte) 0xf2, (byte) 0x0e, (byte) 0xf4, (byte) 0xdb, (byte) 0x19, (byte) 0x75, (byte) 0xc4,
			(byte) 0xea, (byte) 0xc2, (byte) 0x57, (byte) 0xa1, (byte) 0x74, (byte) 0x33, (byte) 0x21, (byte) 0x75,
			(byte) 0xe9, (byte) 0x12, (byte) 0x07, (byte) 0x8d, (byte) 0x7f, (byte) 0xc4, (byte) 0xa3, (byte) 0xa2,
			(byte) 0xea, (byte) 0x5b, (byte) 0x85, (byte) 0x0c, (byte) 0xdb, (byte) 0x5f, (byte) 0x41, (byte) 0x45,
			(byte) 0x26, (byte) 0xf4, (byte) 0x90, (byte) 0xba, (byte) 0x88, (byte) 0xf4, (byte) 0x90, (byte) 0xfd,
			(byte) 0xce, (byte) 0x36, (byte) 0xdc, (byte) 0xe2, (byte) 0x17, (byte) 0x8f, (byte) 0x4a, (byte) 0x8f,
			(byte) 0x8d, (byte) 0x90, (byte) 0x27, (byte) 0xbc, (byte) 0x2d, (byte) 0xa5, (byte) 0x2c, (byte) 0x8e,
			(byte) 0x7d, (byte) 0x83, (byte) 0x76, (byte) 0x6d, (byte) 0xdd, (byte) 0x3b, (byte) 0xe9, (byte) 0xab,
			(byte) 0x91, (byte) 0x6e, (byte) 0xc3, (byte) 0xb2, (byte) 0x89, (byte) 0xca, (byte) 0xeb, (byte) 0x00,
			(byte) 0xed, (byte) 0xa4, (byte) 0x0e
	};
	static byte[] signatureModifiedMessageBytes_groupB = new byte[] { 
			(byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x2b, (byte) 0x74, (byte) 0x3b, (byte) 0x19, (byte) 0xca,
			(byte) 0x7e, (byte) 0xb6, (byte) 0xe6, (byte) 0x70, (byte) 0x9a, (byte) 0x19, (byte) 0xFF, (byte) 0x06,
			(byte) 0xbb, (byte) 0xbb, (byte) 0xbb, (byte) 0x57, (byte) 0xf0, (byte) 0x5c, (byte) 0x22, (byte) 0xff,
			(byte) 0x8b, (byte) 0x84, (byte) 0xaf, (byte) 0xcb, (byte) 0xa1, (byte) 0x4b, (byte) 0xe5, (byte) 0xcb,
			(byte) 0x03, (byte) 0x52, (byte) 0x10, (byte) 0x01, (byte) 0xec, (byte) 0xb2, (byte) 0x31, (byte) 0x9b,
			(byte) 0xe5, (byte) 0xaf, (byte) 0xec, (byte) 0x75, (byte) 0x53, (byte) 0x12, (byte) 0xbb, (byte) 0x6b,
			(byte) 0x98, (byte) 0xce, (byte) 0xb4, (byte) 0x76, (byte) 0xb6, (byte) 0xdb, (byte) 0x59, (byte) 0x71,
			(byte) 0xcc, (byte) 0x73, (byte) 0x87, (byte) 0x33, (byte) 0x75, (byte) 0xcd, (byte) 0x7b, (byte) 0xb0,
			(byte) 0x58, (byte) 0xcd, (byte) 0x97, (byte) 0x2e, (byte) 0xe0, (byte) 0x6a, (byte) 0x1e, (byte) 0x83,
			(byte) 0x26, (byte) 0x6e, (byte) 0x5f, (byte) 0x68, (byte) 0x47, (byte) 0x49, (byte) 0xb6, (byte) 0x25,
			(byte) 0xf7, (byte) 0x7c, (byte) 0x78, (byte) 0x50, (byte) 0x3d, (byte) 0xd8, (byte) 0xc1, (byte) 0x56,
			(byte) 0xee, (byte) 0xb3, (byte) 0x93, (byte) 0x96, (byte) 0x37, (byte) 0xce, (byte) 0x5f, (byte) 0xea,
			(byte) 0xb7, (byte) 0x76, (byte) 0x9c, (byte) 0x31, (byte) 0x24, (byte) 0x24, (byte) 0xf6, (byte) 0x95,
			(byte) 0x30, (byte) 0x57, (byte) 0x74, (byte) 0xac, (byte) 0xc9, (byte) 0x08
	};
	
	
	//Multicast IP for Group A
	static final InetAddress groupA_multicastIP = new InetSocketAddress("224.0.1.191", 0).getAddress();
		
	//Multicast IP for Group B
	static final InetAddress groupB_multicastIP = new InetSocketAddress("224.0.1.192", 0).getAddress();

	public static void main(String[] args) throws Exception {
		
		//Prepare rarser for the request bytes and creating Request objects 
		UdpDataParser parser = new UdpDataParser();
		Request replayRequest = null;
		Request ciphertextModifiedRequest = null;
		Request signatureModifiedRequest = null;
		
		//Allow the user to provide input on what to do
		Scanner scanner = new Scanner(System.in);
		
		System.out.println("Enter group to send to: ");
		String targetGroup = scanner.next();
		
		System.out.println("Enter type of attack (ciphertext/signature/replay): ");
		String attackType = scanner.next();
		
		scanner.close();
		
		//Set multicast IP depending on the user input
		InetAddress multicastIP = null;
		if(targetGroup.toLowerCase().equals("group1") || targetGroup.toLowerCase().equals("groupA".toLowerCase())) {
			replayRequest = (Request)parser.parseMessage(replayMessageBytes_groupA);
			ciphertextModifiedRequest = (Request)parser.parseMessage(ciphertextModifiedMessageBytes_groupA);	
			signatureModifiedRequest = (Request)parser.parseMessage(signatureModifiedMessageBytes_groupA);	
			multicastIP = groupA_multicastIP;
		} else if(targetGroup.toLowerCase().equals("group2") || targetGroup.toLowerCase().equals("groupB".toLowerCase())) {
			replayRequest = (Request)parser.parseMessage(replayMessageBytes_groupB);
			ciphertextModifiedRequest = (Request)parser.parseMessage(ciphertextModifiedMessageBytes_groupB);	
			signatureModifiedRequest = (Request)parser.parseMessage(signatureModifiedMessageBytes_groupB);
			multicastIP = groupB_multicastIP;
		} else {
			System.out.println("Unknown group!");
			System.exit(0);
		}
		
		//Set request content depending on the user input
		Request multicastRequest = null;
		if(attackType.toLowerCase().equals("ciphertext")) {
			multicastRequest = ciphertextModifiedRequest;
		} else if(attackType.toLowerCase().equals("replay")) {
			multicastRequest = replayRequest;
		} else if(attackType.toLowerCase().equals("signature")) {
			multicastRequest = signatureModifiedRequest;
		} else {
			System.out.println("Unknown attack type!");
			System.exit(0);
		}
		
		//URI to perform request against. Need to check for IPv6 to surround it with []
		String requestURI;
		if(multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort;
		}

		//Now prepare to send request
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);	
		client.setURI(requestURI); //FIXME: ?

		//Information about the sender
		System.out.println("==================");
		System.out.println("*Adversary Multicast sender");
		System.out.println("Uses OSCORE: " + multicastRequest.getOptions().hasOscore());
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		//System.out.println("Request method: " + multicastRequest.getCode());
		//System.out.println("Request payload: " + requestPayload);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		System.out.println("Request OSCORE option: " + Utils.toHexString(multicastRequest.getOptions().getOscore()));
		System.out.print("*");
		
		System.out.println("");
		System.out.println("Adversary is sending a request.");
			
		try {
			String host = new URI(client.getURI()).getHost();
			int port = new URI(client.getURI()).getPort();
			System.out.println("Sending to: " + host + ":" + port);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}
		System.out.println("Sending from: " + client.getEndpoint().getAddress());
		System.out.println(prettyPrintHexPayload(multicastRequest));
	
		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT));
	
		Thread.sleep(1000);

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
	
	/**
	 * Formats a {@link Request} into a readable String representation. 
	 * Prints the payload in hex representation.
	 * 
	 * @param r the Request
	 * @return the pretty print
	 */
	public static String prettyPrintHexPayload(Request r) {

		StringBuilder sb = new StringBuilder();

		sb.append("==[ CoAP Request ]=============================================").append(StringUtil.lineSeparator());
		sb.append(String.format("MID    : %d", r.getMID())).append(StringUtil.lineSeparator());
		sb.append(String.format("Token  : %s", r.getTokenString())).append(StringUtil.lineSeparator());
		sb.append(String.format("Type   : %s", r.getType().toString())).append(StringUtil.lineSeparator());
		sb.append(String.format("Method : %s", r.getCode().toString())).append(StringUtil.lineSeparator());
		sb.append(String.format("Options: %s", r.getOptions().toString())).append(StringUtil.lineSeparator());
		sb.append(String.format("Payload: %d Bytes", r.getPayloadSize())).append(StringUtil.lineSeparator());
		if (r.getPayloadSize() > 0 && MediaTypeRegistry.isPrintable(r.getOptions().getContentFormat())) {
			sb.append("---------------------------------------------------------------").append(StringUtil.lineSeparator());
			sb.append(Utils.toHexString(r.getPayload()));
			sb.append(StringUtil.lineSeparator());
		}
		sb.append("===============================================================");

		return sb.toString();
	}
}
