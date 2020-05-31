package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class GroupOSCORESenderReceiverTest {

	@Test
	public void testOneRecipient() throws Exception {

		Thread.sleep(1000);

		GroupOSCOREReceiver receiver = new GroupOSCOREReceiver();
		GroupOSCORESender sender = new GroupOSCORESender();

		receiver.startServer(false); // Recipient #1
		List<CoapResponse> responseList = sender.sendRequest();

		System.out.println("Responses: ");
		for (int i = 0; i < responseList.size(); i++) {
			System.out.println(Utils.prettyPrint(responseList.get(i)));
		}

		// Should get 1 response
		assertEquals(1, responseList.size());

		CoapResponse response = responseList.get(0);

		int payloadLength = response.getPayload().length;
		assertTrue("mynum is out of range: " + payloadLength, 11 <= payloadLength && payloadLength <= 13);

		assertEquals("TEST. ID: ", response.getResponseText().substring(0, 10));

		assertEquals(Type.NON, response.advanced().getType());

		assertEquals(ResponseCode.CONTENT, response.getCode());

		assertArrayEquals(new byte[] { 0x08, 0x52 }, response.getOptions().getOscore());

		// receiver.purge();
		// sender.purge();
	}

	@Test
	public void testOneRecipientAlt() throws Exception {

		Thread.sleep(1000);

		GroupOSCOREReceiver receiver = new GroupOSCOREReceiver();
		GroupOSCORESender sender = new GroupOSCORESender();

		receiver.startServer(true); // Recipient #2
		List<CoapResponse> responseList = sender.sendRequest();

		System.out.println("Responses: ");
		for (int i = 0; i < responseList.size(); i++) {
			System.out.println(Utils.prettyPrint(responseList.get(i)));
		}

		// Should get 1 response
		assertEquals(1, responseList.size());

		CoapResponse response = responseList.get(0);

		int payloadLength = response.getPayload().length;
		assertTrue("mynum is out of range: " + payloadLength, 11 <= payloadLength && payloadLength <= 13);

		assertEquals("TEST. ID: ", response.getResponseText().substring(0, 10));

		assertEquals(Type.NON, response.advanced().getType());

		assertEquals(ResponseCode.CONTENT, response.getCode());

		assertArrayEquals(new byte[] { 0x08, 0x77 }, response.getOptions().getOscore());

		// receiver.purge();
		// sender.purge();
	}

	@Test
	public void testResponsesMultiple() throws Exception {

		Thread.sleep(1000);

		GroupOSCOREReceiver receiver = new GroupOSCOREReceiver();
		GroupOSCORESender sender = new GroupOSCORESender();

		receiver.startServer(false); // Recipient #2
		receiver.startServer(true); // Recipient #2
		List<CoapResponse> responseList = sender.sendRequest();

		System.out.println("Responses: ");
		for (int i = 0; i < responseList.size(); i++) {
			System.out.println(Utils.prettyPrint(responseList.get(i)));
		}

		// Should get 2 responses
		assertEquals(2, responseList.size());

		CoapResponse response = responseList.get(0);

		int payloadLength = response.getPayload().length;
		assertTrue("mynum is out of range: " + payloadLength, 11 <= payloadLength && payloadLength <= 13);

		assertEquals("TEST. ID: ", response.getResponseText().substring(0, 10));

		assertEquals(Type.NON, response.advanced().getType());

		assertEquals(ResponseCode.CONTENT, response.getCode());

		assertArrayEquals(new byte[] { 0x08, 0x77 }, response.getOptions().getOscore());

		assertEquals(responseList.get(0).advanced().getToken(), responseList.get(1).advanced().getToken());

		assertNotEquals(responseList.get(0).advanced().getMID(), responseList.get(1).advanced().getMID());

		assertNotEquals(responseList.get(0).getResponseText(), responseList.get(1).getResponseText());

		// receiver.purge();
		// sender.purge();
	}

	/**
	 * Class implementing receiver.
	 */
	public static class GroupOSCOREReceiver {

		/**
		 * Controls whether or not the receiver will reply to incoming multicast
		 * non-confirmable requests.
		 * 
		 * The receiver will always reply to confirmable requests (can be used
		 * with unicast).
		 * 
		 */
		static final boolean replyToNonConfirmable = true;

		/**
		 * Whether to use OSCORE or not.
		 */
		static final boolean useOSCORE = true;

		/**
		 * Give the receiver a random unicast IP (from the loopback 127.0.0.0/8
		 * range) FIXME: Communication does not work with this turned on
		 */
		static final boolean randomUnicastIP = false;

		/**
		 * Multicast address to listen to (use the first line to set a custom
		 * one).
		 */
		// static final InetAddress multicastIP = new
		// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
		static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

		/**
		 * Port to listen to.
		 */
		static final int listenPort = CoAP.DEFAULT_COAP_PORT;

		/**
		 * ED25519 curve value.
		 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
		 */
		static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); // Integer
																	// value 6

		/* --- OSCORE Security Context information (receiver) --- */
		private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
		private final static String uriLocal = "coap://localhost";
		private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

		// Group OSCORE specific values for the countersignature
		private final static AlgorithmID alg_countersign = AlgorithmID.EDDSA;
		private final static Integer par_countersign = ED25519; // Ed25519

		// test vector OSCORE draft Appendix C.1.2
		private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
		private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
				(byte) 0x78, (byte) 0x63, (byte) 0x40 };

		/*
		 * Rikard: Note regarding countersignature keys. The sid_private_key
		 * contains both the public and private keys. The rid*_public_key
		 * contains only the public key. For information on the keys see the
		 * Countersign_Keys file.
		 */

		private static byte[] sid = new byte[] { 0x52 };
		private static String sid_private_key_string = "pQMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0YzibI1gghX62HT9tcKJ4o2dA0TLAmfYogO1Jfie9/UaF+howTyY=";
		private static OneKey sid_private_key;

		private final static byte[] rid1 = new byte[] { 0x25 };
		private final static String rid1_public_key_string = "pAMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6";
		private static OneKey rid1_public_key;

		private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // Group
																						// ID
		/* --- OSCORE Security Context information --- */

		private static Random random;

		public void purge() {
			db.purge();
		}

		public void startServer(boolean recipientTwoSettings) throws Exception {
			// Install cryptographic providers
			Provider PROVIDER = new BouncyCastleProvider();
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(PROVIDER, 1);
			Security.insertProviderAt(EdDSA, 0);

			// Set sender & receiver keys for countersignatures
			sid_private_key = new OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));
			rid1_public_key = new OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rid1_public_key_string)));

			if (recipientTwoSettings) {
				System.out.println("Starting with alternative sid 0x77.");
				sid = new byte[] { 0x77 };
				sid_private_key_string = "pQMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bouI1gge/Yvdn7Rz0xgkR/En9/Mub1HzH6fr0HLZjadXIUIsjk=";
				sid_private_key = new OneKey(
						CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));
			} else {
				System.out.println("Starting with sid 0x52.");
			}

			// If OSCORE is being used set the context information
			GroupOSCoreCtx ctx = null;
			if (useOSCORE) {
				ctx = new GroupOSCoreCtx(master_secret, true, alg, sid, kdf, 32, master_salt,
						group_identifier, alg_countersign, par_countersign, sid_private_key);
				ctx.addRecipientContext(rid1, rid1_public_key);
				db.addContext(uriLocal, ctx);

				OSCoreCoapStackFactory.useAsDefault();
			}

			// Initialize random number generator
			random = new Random();

			NetworkConfig config = NetworkConfig.getStandard();
			CoapEndpoint endpoint = createEndpoints(config);
			CoapServer server = new CoapServer(config);
			server.addEndpoint(endpoint);
			server.add(new HelloWorldResource(rid1, ctx, db, uriLocal));

			// Information about the receiver
			System.out.println("==================");
			System.out.println("*Multicast receiver");
			System.out.println("Uses OSCORE: " + useOSCORE);
			System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
			System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
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

		private CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {
			int port = listenPort;

			InetSocketAddress localAddress;
			// Set a random loopback address in 127.0.0.0/8
			if (randomUnicastIP) {
				byte[] b = new byte[4];
				random.nextBytes(b);
				b[0] = 127;
				b[1] = 0;
				InetAddress inetAdd = InetAddress.getByAddress(b);

				localAddress = new InetSocketAddress(inetAdd, port);
			} else { // Set the wildcard address (0.0.0.0)
				localAddress = new InetSocketAddress(port);
			}

			Connector connector = new UdpMulticastConnector(localAddress, multicastIP);
			return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
		}

		private class HelloWorldResource extends CoapResource {

			private int id;
			private int count = 0;

			GroupOSCoreCtx myCtx;
			HashMapCtxDB db;
			String uriLocal;
			byte[] myRid;

			private HelloWorldResource(byte[] myRid, GroupOSCoreCtx myCtx, HashMapCtxDB db, String uriLocal) {
				// set resource identifier
				super("helloWorld"); // Changed

				// set display name
				getAttributes().setTitle("Hello-World Resource");

				id = random.nextInt(1000);

				System.out.println("coap receiver: " + id);

				this.myCtx = myCtx;
				this.db = db;
				this.uriLocal = uriLocal;
				this.myRid = myRid;

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

				// respond to the request if confirmable or replies are set to
				// be sent for non-confirmable
				// payload is set to request payload changed to uppercase plus
				// the receiver ID
				if (isConfirmable || replyToNonConfirmable) {
					Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
					r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
					if (isConfirmable) {
						r.setType(Type.ACK);
					} else {
						r.setType(Type.NON);
					}

					System.out.println();
					System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
					System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress()); // Taken
																											// from
																											// exchange
					System.out.println(Utils.prettyPrint(r));

					if (count == 1) {

						exchange.respond(r);
						//
						// db.removeContext(this.myRid);
						// try {
						// this.db.addContext(this.uriLocal, this.myCtx);
						// } catch (OSException e) {
						// // TODO Auto-generated catch block
						// e.printStackTrace();
						// }

					}


				}

			}

		}
	}

	/**
	 * Test sender configured to support multicast requests.
	 */
	public class GroupOSCORESender {

		/**
		 * File name for network configuration.
		 */
		private final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
		/**
		 * Header for network configuration.
		 */
		private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
		/**
		 * Special network configuration defaults handler.
		 */
		private NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

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
		 * Multicast address to send to (use the first line to set a custom
		 * one).
		 */
		// static final InetAddress multicastIP = new
		// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
		final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

		/**
		 * Port to send to.
		 */
		private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

		/**
		 * Resource to perform request against.
		 */
		static final String requestResource = "/helloWorld";

		/**
		 * Payload in request sent (POST)
		 */
		static final String requestPayload = "test";

		/**
		 * ED25519 curve value.
		 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
		 */
		final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); // Integer
																	// value 6

		/* --- OSCORE Security Context information (sender) --- */
		private final HashMapCtxDB db = HashMapCtxDB.getInstance();
		private final AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		private final AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

		// Group OSCORE specific values for the countersignature
		private final AlgorithmID alg_countersign = AlgorithmID.EDDSA;
		private final Integer par_countersign = ED25519; // Ed25519

		// test vector OSCORE draft Appendix C.1.1
		private final byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
		private final byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
				(byte) 0x78, (byte) 0x63, (byte) 0x40 };

		/*
		 * Rikard: Note regarding countersignature keys. The sid_private_key
		 * contains both the public and private keys. The rid*_public_key
		 * contains only the public key. For information on the keys see the
		 * Countersign_Keys file.
		 */

		private final byte[] sid = new byte[] { 0x25 };
		private final static String sid_private_key_string = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
		private OneKey sid_private_key;

		private final byte[] rid1 = new byte[] { 0x52 }; // Recipient 1
		private final static String rid1_public_key_string = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
		private OneKey rid1_public_key;

		private final byte[] rid2 = new byte[] { 0x77 }; // Recipient 2
		private final static String rid2_public_key_string = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
		private OneKey rid2_public_key;

		private final byte[] rid0 = new byte[] { (byte) 0xCC }; // Does
																		// not
																		// exist

		private final byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // Group
																						// ID
		/* --- OSCORE Security Context information --- */

		public void purge() {
			db.purge();
		}

		public List<CoapResponse> sendRequest() throws Exception {
			/**
			 * URI to perform request against. Need to check for IPv6 to
			 * surround it with []
			 */
			String requestURI;
			if (multicastIP instanceof Inet6Address) {
				requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort
						+ requestResource;
			} else {
				requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
			}

			// Install cryptographic providers
			Provider PROVIDER = new BouncyCastleProvider();
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(PROVIDER, 1);
			Security.insertProviderAt(EdDSA, 0);
			// InstallCryptoProviders.generateCounterSignKey(); //For generating
			// keys

			// Add private & public keys for sender & receiver(s)
			sid_private_key = new OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));
			rid1_public_key = new OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rid1_public_key_string)));
			rid2_public_key = new OneKey(
					CBORObject.DecodeFromBytes(Base64.getDecoder().decode(rid2_public_key_string)));

			// If OSCORE is being used set the context information
			if (useOSCORE) {
				GroupOSCoreCtx ctx = new GroupOSCoreCtx(master_secret, true, alg, sid, kdf, 32, master_salt,
						group_identifier, alg_countersign, par_countersign, sid_private_key);
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
			if (useOSCORE) {
				multicastRequest.getOptions().setOscore(new byte[0]); // Set the
																		// OSCORE
																		// option
			}

			// Information about the sender
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

			handler = new MultiCoapHandler();

			// sends a multicast request
			client.advanced(handler, multicastRequest);
			while (handler.waitOn(HANDLER_TIMEOUT))
				;

			// Return all responses
			return handler.getResponseList();
		}

		private MultiCoapHandler handler = null;

		private class MultiCoapHandler implements CoapHandler {

			// List to hold all responses
			List<CoapResponse> responseList = new ArrayList<CoapResponse>();

			public List<CoapResponse> getResponseList() {
				return responseList;
			}

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

				responseList.add(response);
			}

			@Override
			public void onError() {
				System.err.println("error");
			}
		};
	}

}
