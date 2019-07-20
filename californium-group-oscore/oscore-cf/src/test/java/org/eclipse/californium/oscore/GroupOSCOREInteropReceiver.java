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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;

/**
 * Group OSCORE interop test receiver application.
 * 
 * See the Contexts class for the definition of context parameters.
 */
public class GroupOSCOREInteropReceiver {
	
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

	/**
	 * String the server will reply with for tests
	 */
	private static String SERVER_RESPONSE = "Hello World!";
	
	/* --- Partial OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static String uriLocal = "coap://localhost";
	
	private static byte[] sid = Contexts.Server_1.sid;
	private static OneKey sid_private_key;
	
	private static Random random;
	
	public static void main(String[] args) throws Exception {
		//Install cryptographic providers
		InstallCryptoProviders.installProvider();
		
		//Set sender & receiver keys for countersignatures
		sid_private_key = new OneKey(Contexts.Server_1.signing_key_cbor);

		//Check command line arguments (flag to use different sid and sid key)
		if(args.length != 0) {
			sid = Contexts.Server_2.sid;
			System.out.println("Starting with alternative sid 0x" + Utility.arrayToString(sid));
			sid_private_key = new OneKey(Contexts.Server_2.signing_key_cbor);
		} else {
			System.out.println("Starting with sid 0x" + Utility.arrayToString(sid));
		}
		
		//If OSCORE is being used set the context information
		if(useOSCORE) {
			
			//Make the OSCORE Group Context
			GroupOSCoreCtx ctx = new GroupOSCoreCtx(
					Contexts.Common.master_secret,
					true,
					Contexts.alg,
					sid,
					Contexts.kdf,
					Contexts.replay_size,
					Contexts.Common.master_salt,
					Contexts.Common.id_context,
					Contexts.Common.alg_countersign,
					Contexts.Common.par_countersign,
					sid_private_key);
			
			//Add the pre-configured recipient contexts
			
			//Add contexts for clients from Jim and Peter
			ctx.addRecipientContext(Contexts.Jim.client_rid, new OneKey(Contexts.Jim.public_key_cbor));
			ctx.addRecipientContext(Contexts.Peter.client_rid, new OneKey(Contexts.Peter.public_key_cbor));
			
			db.addContext(uriLocal, ctx);

			OSCoreCoapStackFactory.useAsDefault();
			
			System.out.println("Current Group OSCORE Context:");
			Utility.printContextInfo(ctx);
		}
		
		//Initialize random number generator
		random = new Random();
		
		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config);
		CoapServer server = new CoapServer(config);
		server.addEndpoint(endpoint);
		
		//Creating resource hierarchy
		
		//Hello resource
		CoapResource root_hello = new CoapResource("hello", true);
		
		//Base resource for OSCORE interop test resources
		OSCoreResource oscore = new OSCoreResource("oscore", true);
		
		//Second level base resource for OSCORE interop test resources
		OSCoreResource oscore_hello = new OSCoreResource("hello", true);
		
		//CoAP resource for OSCORE interop tests
		CoapResource oscore_hello_coap = new OSCoreHelloCoAP("coap", true);
		
		//1 resource for OSCORE interop tests
		OSCoreResource oscore_hello_1 = new OSCoreHello1("1", true);
		
		oscore_hello.add(oscore_hello_coap);				
		oscore_hello.add(oscore_hello_1);
		oscore.add(oscore_hello);
		server.add(oscore);
		server.add(root_hello);
		server.add(new HelloWorldResource());
		
		//Information about the receiver
		System.out.println("==================");
		System.out.println("Multicast receiver");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Multicast IP: " + CoAP.MULTICAST_IPV4);
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + endpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for(Resource resDepth1 : server.getRoot().getChildren()) {
			System.out.print(resDepth1.getURI() + " ");
			for(Resource resDepth2 : resDepth1.getChildren()) {
				System.out.print(resDepth2.getURI() + " ");
				for(Resource resDepth3 : resDepth2.getChildren()) {
					System.out.print(resDepth3.getURI() + " ");
				}
			}
		}
		System.out.println("");	
		System.out.println("==================");		
		
		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {
		int port = config.getInt(Keys.COAP_PORT);
		
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
		
		Connector connector = new UdpMulticastConnector(localAddress, CoAP.MULTICAST_IPV4);
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
	}

	//Hello world resource that additionally replies with an ID
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
	
	/** --- Resources for interop tests follow --- **/
	
	//CoAP resource for OSCORE interop tests
	static class OSCoreHelloCoAP extends CoapResource {

		public OSCoreHelloCoAP(String name, boolean isProtected) {
			super(name, isProtected);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response r = new Response(ResponseCode.CONTENT);
			r.setPayload(SERVER_RESPONSE);
			r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			
			exchange.respond(r);
		}
	};
	
	//1 resource for OSCORE interop tests
	static class OSCoreHello1 extends OSCoreResource {
		public OSCoreHello1(String name, boolean isProtected) {
			super(name, isProtected);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response r = new Response(ResponseCode.CONTENT);
			r.setPayload(SERVER_RESPONSE);
			r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

			exchange.respond(r);
		}
	};
}
