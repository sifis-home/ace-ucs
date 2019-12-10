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
 *    Rikard HÃ¶glund (RISE SICS)
 ******************************************************************************/
package se.sics.prototype.apps;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.Utility;

import com.upokecenter.cbor.CBORObject;

import se.sics.prototype.support.KeyStorage;


/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOscoreServer {
	
	/**
	 * Controls whether or not the receiver will reply to incoming multicast non-confirmable requests.
	 * 
	 * The receiver will always reply to confirmable requests (can be used with unicast).
	 *  
	 */
	static final boolean replyToNonConfirmable = true;
	
	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;
	
	/**
	 * Give the receiver a random unicast IP (from the loopback 127.0.0.0/8 range)
	 * FIXME: Communication does not work with this turned on
	 */
	static final boolean randomUnicastIP = false;
	
//	/**
//	 * Multicast address to listen to (use the first line to set a custom one).
//	 */
//	//static final InetAddress multicastIP = new InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
//	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to listen to.
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT - 1000;

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	
	/**
	 * OSCORE Security Context database (receiver)
	 */
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	
	private final static String uriLocal = "coap://localhost";
	
	private static Random random;
	
	public static void start(GroupOSCoreCtx derivedCtx, InetAddress multicastIP) throws Exception {
		//Install cryptographic providers
		InstallCryptoProviders.installProvider();
		
		//If OSCORE is being used set the context information
		GroupOSCoreCtx ctx = null;
		if(useOSCORE) {
			ctx = derivedCtx;
			
			//Add recipient contexts for the 2 clients
			String keyClient1_base64 = KeyStorage.publicKeys.get("Client1");
			byte[] sidClient1 = KeyStorage.clientSenderIDs.get(keyClient1_base64).getBytes();
			OneKey keyClient1 = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyClient1_base64)));
			ctx.addRecipientContext(sidClient1, keyClient1);
			
			String keyClient2_base64 = KeyStorage.publicKeys.get("Client2");
			byte[] sidClient2 = KeyStorage.clientSenderIDs.get(keyClient2_base64).getBytes();
			OneKey keyClient2 = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyClient2_base64)));
			ctx.addRecipientContext(sidClient2, keyClient2);
			
			//Add the completed context to the context database
			db.addContext(uriLocal, ctx);

			//OSCoreCoapStackFactory.useAsDefault();
		}
		
		//Initialize random number generator
		random = new Random();
		
		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config, multicastIP);
		CoapServer server = new CoapServer(config);
		server.addEndpoint(endpoint);
		server.add(new HelloWorldResource());
		server.add(new ToggleResource());
		
		//Information about the receiver
		System.out.println("==================");
		System.out.println("*Multicast receiver");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + endpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for(Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		
		System.out.print("*");
		Utility.printContextInfo(ctx);
		System.out.println("==================");
		
		System.out.println("");
		System.out.println("Server has joined the group. Waiting for requests.");
		
		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config, InetAddress multicastIP) throws UnknownHostException {
		int port = listenPort;
		
		InetSocketAddress localAddress;
		//Set a random loopback address in 127.0.0.0/8
		if(randomUnicastIP) {
			byte[] b = new byte[4];
			random.nextBytes(b);
			b[0] = 127;
			b[1] = 0;
			InetAddress inetAdd = InetAddress.getByAddress(b);
			
			localAddress = new InetSocketAddress(inetAdd, port);
		} else { //Set the wildcard address (0.0.0.0)
			localAddress = new InetSocketAddress(port);
		}
		
		Connector connector = new UdpMulticastConnector(localAddress, multicastIP);
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
	}
	
	private static class ToggleResource extends CoapResource {

		private int id;
		private int count = 0;
		private boolean stateOn = false;

		private ToggleResource() {
			// set resource identifier
			super("toggle"); //Changed
			
			// set display name
			getAttributes().setTitle("Toggle Resource");
			
			id = random.nextInt(1000);
			
			System.out.println("coap receiver: " + id);
		}
		
		//Added for handling GET
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
			
			if(exchange.getRequestText().toLowerCase().equals("off")) {
				System.out.println("*** Turning OFF LEDs/solenoids ***");
				stateOn = false;
				//Run script to turn off
			} else if(exchange.getRequestText().toLowerCase().equals("on")) {
				System.out.println("*** Turning ON LEDs/solenoids ***");
				stateOn = true;
				//Run script to turn on
			} else {
				System.out.println("*** Toggling LEDs/solenoids ***");
				stateOn = !stateOn;
				System.out.println("They are now turned on :" + stateOn);
				//Run script to turn on or off
			}
			
			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();
			
			// respond to the request if confirmable or replies are set to be sent for non-confirmable
			// payload is set to request payload changed to uppercase plus the receiver ID
			if(isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
				if(isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}
				
				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress()); //Taken from exchange
				System.out.println(Utils.prettyPrint(r));
				
				exchange.respond(r);
			}
			
		}
		
	}

	private static class HelloWorldResource extends CoapResource {

		private int id;
		private int count = 0;

		private HelloWorldResource() {
			// set resource identifier
			super("helloWorld"); //Changed
			
			// set display name
			getAttributes().setTitle("Hello-World Resource");
			
			id = random.nextInt(1000);
			
			System.out.println("coap receiver: " + id);
		}
		
		//Added for handling GET
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
			
			// respond to the request if confirmable or replies are set to be sent for non-confirmable
			// payload is set to request payload changed to uppercase plus the receiver ID
			if(isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
				if(isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}
				
				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress()); //Taken from exchange
				System.out.println(Utils.prettyPrint(r));
				
				exchange.respond(r);
			}
			
		}
		
	}
}
