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
	static byte[] replayMessageBytes = new byte[] { (byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x3d,
			(byte) 0xba, (byte) 0x9f, (byte) 0xbe, (byte) 0x38, (byte) 0x4c, (byte) 0x22, (byte) 0x91, (byte) 0x54,
			(byte) 0x90, (byte) 0x26, (byte) 0x74, (byte) 0x6f, (byte) 0x67, (byte) 0x67, (byte) 0x6c, (byte) 0x65,
			(byte) 0xff, (byte) 0x3f, (byte) 0x2e };
	
	/**
	 * Decryption failed message for the adversary to send
	 */
	static byte[] decryptionFailedMessageBytes = new byte[] { (byte) 0x58, (byte) 0x02, (byte) 0xff, (byte) 0x3d,
			(byte) 0xba, (byte) 0x9f, (byte) 0xbe, (byte) 0x38, (byte) 0x4c, (byte) 0x22, (byte) 0x91, (byte) 0x54,
			(byte) 0x90, (byte) 0x26, (byte) 0x74, (byte) 0x6f, (byte) 0x67, (byte) 0x67, (byte) 0x6c, (byte) 0x65,
			(byte) 0xff, (byte) 0x3f, (byte) 0x2e };
	
	//Multicast IP for Group A
	static final InetAddress groupA_multicastIP = new InetSocketAddress("224.0.1.191", 0).getAddress();
		
	//Multicast IP for Group B
	static final InetAddress groupB_multicastIP = new InetSocketAddress("224.0.1.192", 0).getAddress();

	public static void main(String[] args) throws Exception {
		
		//Parse the request bytes and create Request objects 
		UdpDataParser parser = new UdpDataParser();
		Request replayRequest = (Request)parser.parseMessage(replayMessageBytes);
		Request decryptionFailedRequest = (Request)parser.parseMessage(decryptionFailedMessageBytes);
		
		//Allow the user to provide input on what to do
		Scanner scanner = new Scanner(System.in);
		
		System.out.println("Enter group to send to: ");
		String targetGroup = scanner.next();
		
		System.out.println("Enter type of attack (normal/replay): ");
		String attackType = scanner.next();
		
		scanner.close();
		
		//Set multicast IP depending on the user input
		InetAddress multicastIP = null;
		if(targetGroup.toLowerCase().equals("group1") || targetGroup.toLowerCase().equals("groupA".toLowerCase())) {
			multicastIP = groupA_multicastIP;
		} else if(targetGroup.toLowerCase().equals("group2") || targetGroup.toLowerCase().equals("groupB".toLowerCase())) {
			multicastIP = groupB_multicastIP;
		} else {
			System.out.println("Unknown group!");
			System.exit(0);
		}
		
		//Set request content depending on the user input
		Request multicastRequest = null;
		if(attackType.toLowerCase().equals("normal")) {
			multicastRequest = decryptionFailedRequest;
		} else if(attackType.toLowerCase().equals("replay")) {
			multicastRequest = replayRequest;
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
