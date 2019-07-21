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
import java.net.URI;
import java.net.URISyntaxException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.OneKey;

import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Group OSCORE interop test sender application.
 * 
 * See the Contexts class for the definition of context parameters.
 * 
 */
public class GroupOSCOREInteropSender {
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

	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);
	
	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 2000;
	
	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

	/**
	 * Whether to use POST to send some data.
	 * Otherwise GET will be used.
	 */
	static final boolean usePOST = false;
	
	/**
	 * URI to perform request against.
	 */
	//static final String requestResource  = "/oscore/hello/1";
	static final String requestResource  = "/.well-known/core";
	//static final String requestIP = "31.133.136.216"; //Jim server #1
	//static final String requestIP = "31.133.155.197"; //Jim server #2
	static final String requestIP = "31.133.156.244"; //Peter server #1
	//static final String requestIP = CoAP.MULTICAST_IPV4.getHostAddress(); //Multicast
	static final String requestURI = "coap://" + requestIP + ":" + COAP_PORT + requestResource;
	
	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "test";

	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static String uri = requestURI;
	
	public static void main(String args[]) throws Exception {
		//Install cryptographic providers
		InstallCryptoProviders.installProvider();
		//InstallCryptoProviders.generateCounterSignKey(); //For generating keys
		
		//Fill list with information about receivers and associated public keys (can be used when getting messages)
		//Can be used when getting messages and a recipient context should be generated
		Contexts.fillRecipientInfo();
		
		//Add private & public keys for sender & pre-configured receiver(s)
		OneKey sid_private_key = new OneKey(Contexts.Client.signing_key_cbor);

		//If OSCORE is being used set the context information
		if(useOSCORE) {
			
			//Make the OSCORE Group Context
			GroupOSCoreCtx ctx = new GroupOSCoreCtx(
					Contexts.Common.master_secret,
					true,
					Contexts.alg,
					Contexts.Client.sid,
					Contexts.kdf,
					Contexts.replay_size,
					Contexts.Common.master_salt,
					Contexts.Common.id_context,
					Contexts.Common.alg_countersign,
					Contexts.Common.par_countersign,
					sid_private_key);
			
			//Add the pre-configured recipient contexts

			//Add contexts for Jim's servers
			ctx.addRecipientContext(Contexts.Jim.server_1_rid, new OneKey(Contexts.Jim.public_key_cbor));
			ctx.addRecipientContext(Contexts.Jim.server_2_rid, new OneKey(Contexts.Jim.public_key_cbor));
			
			//Add contexts for Peter's servers
			ctx.addRecipientContext(Contexts.Peter.server_1_rid, new OneKey(Contexts.Peter.public_key_cbor));
			ctx.addRecipientContext(Contexts.Peter.server_2_rid, new OneKey(Contexts.Peter.public_key_cbor));
			
			db.addContext(uri, ctx);

			OSCoreCoapStackFactory.useAsDefault();
	
			System.out.println("Current Group OSCORE Context:");
			Utility.printContextInfo(ctx);
		}
		
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);
		
		client.setURI(requestURI);
		
		Request multicastRequest;
		if(usePOST)
		{
			multicastRequest = Request.newPost();
			multicastRequest.setPayload(requestPayload);
		} else {
			multicastRequest = Request.newGet();
		}
		
		multicastRequest.setType(Type.NON);
		if(useOSCORE) {
			multicastRequest.getOptions().setOscore(new byte[0]); //Set the OSCORE option
		}

		//Information about the sender
		System.out.println("==================");
		System.out.println("Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
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
			
			System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};
}
