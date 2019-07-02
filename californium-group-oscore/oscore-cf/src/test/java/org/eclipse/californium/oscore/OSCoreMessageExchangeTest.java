/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - destroy server after test
 *    Rikard Höglund (RISE SICS) - testing OSCORE messages
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Performs tests of different types of message exchanges between an OSCORE server and client
 * Based on interoperability test specification created by Ericsson:
 * https://ericssonresearch.github.io/OSCOAP/test-spec5.html
 * 
 */
@Category(Large.class)
public class OSCoreMessageExchangeTest {

	private static String SERVER_RESPONSE = "Hello World!";

	private CoapServer server;
	private int serverPort;
	private static String serverAddress = InetAddress.getLoopbackAddress().getHostAddress();
	
	private static String clientAddress = InetAddress.getLoopbackAddress().getHostName();
	
	//OSCORE context information shared between server and client
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] id_context = { (byte) 0x37, (byte) 0xcb, (byte) 0xf3, (byte) 0x21, (byte) 0x00, (byte) 0x17, (byte) 0xa2, (byte) 0xd3 };
	
	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}
	
	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault();
	}

	//FIXME: Start server in (at)Before?
	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}
	
	/* --- Client interop tests follow --- */ 
	
	/**
	 * Create an OSCORE request to be set from a client to the server
	 * 
	 * @param c Code of request
	 * @param resourceUri Relative URI of resource
	 * @return The request
	 */
	private Request createClientRequest(Code c, String resourceUri) {
		String serverUri = "coap://" + serverAddress + ":" + serverPort;
		
		Request r = new Request(c);
				
		r.setConfirmable(true);
		r.setURI(serverUri + resourceUri);
		r.getOptions().setOscore(new byte[0]); //Use OSCORE
		
		return r;
	}
	
	@Test
	public void TEST_0a() throws InterruptedException {	
		String serverUri = "coap://" + serverAddress + ":" + serverPort; 
		String resourceUri = "/oscore/hello/coap";
		Request r = new Request(Code.GET);
		r.setConfirmable(true);
		r.setURI(serverUri + resourceUri);
		r.send();

		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
	}
	
	@Test
	public void TEST_1a() throws InterruptedException {
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
	}
	
	@Test
	public void TEST_2a() throws InterruptedException, OSException {
		//Use ID_Context for this test (re-set the OSCORE contexts for client and server)
		db.addContext("coap://" + serverAddress, new OSCoreCtx(master_secret, true, alg, new byte[0], new byte[] { 0x01 }, kdf, 32, master_salt, id_context));
		db.addContext("coap://" + clientAddress, new OSCoreCtx(master_secret, true, alg, new byte[] { 0x01 }, new byte[0], kdf, 32, master_salt, id_context));
		
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
	}
	
	@Test
	public void TEST_3a() throws InterruptedException {
		String resourceUri = "/oscore/hello/2";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.getOptions().setUriQuery("first=1");
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
		
		assertEquals(resp.getOptions().getETags().get(0)[0], 0x2b);	
	}

	@Test
	public void TEST_4a() throws InterruptedException {
		String resourceUri = "/oscore/hello/3";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.getOptions().setAccept(MediaTypeRegistry.TEXT_PLAIN);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
		
		Long correct = (long) 0x05;
		assertEquals(resp.getOptions().getMaxAge(), correct);
	}
	
	@Test
	public void TEST_5a() throws InterruptedException {
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.setObserve();
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
	}
	
	@Test
	public void TEST_8a() throws InterruptedException {	
		String resourceUri = "/oscore/hello/6";
		Request r = createClientRequest(Code.POST, resourceUri);
		r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		r.setPayload(new byte[] { 0x4a });
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CHANGED);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayload()[0], 0x4a);
	}
	
	@Test
	public void TEST_9a() throws InterruptedException {
		String resourceUri = "/oscore/hello/7";
		Request r = createClientRequest(Code.PUT, resourceUri);
		r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		r.getOptions().addIfMatch(new byte[] { 0x7b });
		r.setPayload(new byte[] { 0x7a });
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CHANGED);
	}
	
	@Test
	public void TEST_10a() throws InterruptedException {
		String resourceUri = "/oscore/hello/7";
		Request r = createClientRequest(Code.PUT, resourceUri);
		r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		r.getOptions().setIfNoneMatch(true);
		r.setPayload(new byte[] { (byte) 0x8a });
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.PRECONDITION_FAILED);
	}
	
	@Test
	public void TEST_11a() throws InterruptedException {
		String resourceUri = "/oscore/test";
		Request r = createClientRequest(Code.DELETE, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.DELETED);
	}
	
	@Test
	public void TEST_12a() throws InterruptedException, OSException {
		byte[] sid_bad = new byte[] { (byte) 0xFF };
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid_bad, rid, kdf, 32, master_salt, null);
		db.addContext("coap://" + serverAddress, ctx);
		
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.UNAUTHORIZED);
		assertEquals(resp.getPayloadString(), ErrorDescriptions.CONTEXT_NOT_FOUND);
	}
	
	@Test
	public void TEST_13a() throws InterruptedException, OSException {
		byte[] sender_key_bad = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01 };
		db.getContext("coap://" + serverAddress).setSenderKey(sender_key_bad);
		
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);

		assertEquals(resp.getCode(), ResponseCode.BAD_REQUEST);
		assertEquals(resp.getPayloadString(), ErrorDescriptions.DECRYPTION_FAILED);
	}
	
	@Test
	public void TEST_15a() throws InterruptedException, OSException {
		int senderSeqNumberBefore = db.getContext("coap://" + serverAddress).getSenderSeq();
		
		String resourceUri = "/oscore/hello/1";
		Request r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getPayloadString(), SERVER_RESPONSE);
		
		//Reset the sender sequence number to before first transmission
		db.getContext("coap://" + serverAddress).setSenderSeq(senderSeqNumberBefore);
	
		//Send message again
		r = createClientRequest(Code.GET, resourceUri);
		r.send();
		
		resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.UNAUTHORIZED);
		assertEquals(resp.getPayloadString(), ErrorDescriptions.REPLAY_DETECT);	
	}
	
	@Test
	public void TEST_17a() throws InterruptedException {
		String serverUri = "coap://" + serverAddress + ":" + serverPort;
		String resourceUri = "/oscore/hello/1";
		Request r = new Request(Code.GET);
		r.setConfirmable(true);
		r.setURI(serverUri + resourceUri);
		r.send();
		
		Response resp = r.waitForResponse(1000);

		assertEquals(resp.getCode(), ResponseCode.UNAUTHORIZED);
	}
	
	/* --- End of client interop tests --- */

	/**
	 * Set OSCORE context information for clients
	 * @throws OSException 
	 */
	@Before
	public void setClientContext() {
		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
	
		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
			db.addContext("coap://" + serverAddress, ctx);
		}
		catch(OSException e) {
			System.err.println("Failed to set client OSCORE Context information!");
		}
	}
	
	/* Server related code below */
	
	/**
	 * (Re)sets the OSCORE context information for the server
	 * @throws OSException 
	 */
	@Before
	public void setServerContext() {
		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		
		try {
			OSCoreCtx ctx_B = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null);
	
			db.addContext("coap://" + clientAddress, ctx_B);
		}
		catch (OSException e) {
			System.err.println("Failed to set server OSCORE Context information!");
		}
	}
	
	/**
	 * Creates server with a number of resources to test OSCORE functionality
	 */
	@Before
	public void createServer() {
		//Do not create server if it is already running
		if(server != null) {
			return;
		}
		
		setServerContext();

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		
		InetAddress serverInetAddress = null;
		try {
			serverInetAddress = InetAddress.getByName(serverAddress);
		} catch (UnknownHostException e) {
			System.err.println("Failed to find server address!");
		}
		
		builder.setInetSocketAddress(new InetSocketAddress(serverInetAddress, 0));
		CoapEndpoint endpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(endpoint);

		/** --- Resources for interop tests follow --- **/
		
		//Base resource for OSCORE interop test resources
		OSCoreResource oscore = new OSCoreResource("oscore", true);
		
		//Second level base resource for OSCORE interop test resources
		OSCoreResource oscore_hello = new OSCoreResource("hello", true);
		
		//CoAP resource for OSCORE interop tests
		CoapResource oscore_hello_coap = new CoapResource("coap", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				
				exchange.respond(r);
			}
		};
		
		//1 resource for OSCORE interop tests
		OSCoreResource oscore_hello_1 = new OSCoreResource("1", true) {
			@Override
			public void handleGET(CoapExchange exchange) {
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

				exchange.respond(r);
			}
		};
		
		//2 resource for OSCORE interop tests
		OSCoreResource oscore_hello_2 = new OSCoreResource("2", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.getOptions().getETags().add(new byte[] { 0x2b });

				exchange.respond(r);
			}
		};
		
		//3 resource for OSCORE interop tests
		OSCoreResource oscore_hello_3 = new OSCoreResource("3", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.getOptions().setMaxAge(5);
				
				exchange.respond(r);
			}
		};
		
		//6 resource for OSCORE interop tests
		OSCoreResource oscore_hello_6 = new OSCoreResource("6", true) {

			private byte[] resourceValue;
			
			@Override
			public void handlePOST(CoapExchange exchange) {
				resourceValue = exchange.getRequestPayload();
				
				Response r = new Response(ResponseCode.CHANGED);
				r.setPayload(resourceValue);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				
				exchange.respond(r);
			}
		};
		
		//7 resource for OSCORE interop tests
		OSCoreResource oscore_hello_7 = new OSCoreResource("7", true) {

			private byte[] resourceValue;
			
			@Override
			public void handlePUT(CoapExchange exchange) {
				//Check if ETag matches or if "If-None-Match" is set
				boolean valid = false;
				byte validETag = 0x7b;
				List<byte[]> ifMatchValues = exchange.advanced().getRequest().getOptions().getIfMatch();
				for(int i = 0 ; i < ifMatchValues.size() ; i++)
					if(ifMatchValues.get(i).length == 1 && ifMatchValues.get(i)[0] == validETag)
						valid = true;
				if(exchange.advanced().getRequest().getOptions().hasIfNoneMatch())
					valid = false;
				
				//Create response depending on validity
				Response r = new Response(ResponseCode.PRECONDITION_FAILED);
				if(valid) {
					resourceValue = exchange.getRequestPayload();
				
					r = new Response(ResponseCode.CHANGED);
					r.setPayload(resourceValue);
					r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
					r.getOptions().getETags().add(new byte[] { validETag });
				}

				exchange.respond(r);
			}
		};
		
		//test resource for OSCORE interop tests
		OSCoreResource oscore_test = new OSCoreResource("test", true) {

			@Override
			public void handleDELETE(CoapExchange exchange) {
				Response r = new Response(ResponseCode.DELETED);
						
				exchange.respond(r);
			}
		};
		
		//Creating resource hierarchy
		oscore_hello.add(oscore_hello_coap);
		
		oscore_hello.add(oscore_hello_1);
		oscore_hello.add(oscore_hello_2);
		oscore_hello.add(oscore_hello_3);
		oscore_hello.add(oscore_hello_6);
		oscore_hello.add(oscore_hello_7);
		
		oscore.add(oscore_hello);
		oscore.add(oscore_test);
		
		server.add(oscore);
		
		/** --- End of resources for interop tests **/
		
		//Start server
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
}
