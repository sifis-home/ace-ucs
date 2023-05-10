/*******************************************************************************
 * Copyright (c) 2023, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.as.logging;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.CountDownLatch;

import org.glassfish.tyrus.client.ClientManager;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jakarta.websocket.ClientEndpoint;
import jakarta.websocket.CloseReason;
import jakarta.websocket.DeploymentException;
import jakarta.websocket.OnClose;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;

/**
 * Handles connection establishment and sending of log messages to the DHT.
 *
 */
@ClientEndpoint
public class DhtLogger {

	private static CountDownLatch latch;
	private static ClientManager dhtClient = null;
	private static Session session = null;
	private static boolean loggingEnabled = false;

	private static String LOG_TOPIC_NAME = "SIFIS:Log";
	private static String LOG_TOPIC_UUID = "Log";

	private static String websocketUri = "ws://localhost:3000/ws";

	private static int LOG_MAX_LEN = 200;

	/**
	 * Sends a logging message to the DHT
	 *
	 * @param type the type
	 * @param priority the priority
	 * @param category the category
	 * @param message the message
	 * @param device the name of the device sending the log message
	 *
	 */
	static public void sendLog(String type, String priority, String category, String device, String message) {

		// Return if DHT logging is not used
		if (loggingEnabled == false) {
			return;
		}

		// Print message to be logged
		System.out.println("[LOG] " + message);

		// If a connection is not established yet (which should
		// have been done from the application), do it now
		if (dhtClient == null || session == null) {
			boolean dhtConnected = establishConnection();

			// If the connection failed to be established, return
			if (dhtConnected == false) {
				return;
			}
		}

		// Build the outgoing JSON payload for the DHT
		JsonOut outgoing = new JsonOut();

		RequestPostTopicUUID requestVal = new RequestPostTopicUUID();
		OutValue valueVal = new OutValue();
		Log logVal = new Log();

		requestVal.setTopicName(LOG_TOPIC_NAME);
		requestVal.setTopicUuid(LOG_TOPIC_UUID);

		logVal.setType(type);
		logVal.setPriority(priority);
		logVal.setCategory(category);

		message = device + ": " + message;
		int maxLen = Math.min(message.length(), LOG_MAX_LEN);
		logVal.setMessage(message.substring(0, maxLen));

		valueVal.setLog(logVal);
		requestVal.setValue(valueVal);
		outgoing.setPayload(requestVal);

		Gson gsonOut = new GsonBuilder().disableHtmlEscaping().create();
		String jsonOut = gsonOut.toJson(outgoing);

		// Now send the payload to the DHT
		try {
			session.getBasicRemote().sendText(jsonOut);
		} catch (IOException e) {
			System.err.println("Error: Sending logging payload to DHT failed");
			e.printStackTrace();
		}
	}

	/**
	 * Enable or disable logging to the DHT
	 *
	 * @param logging true/false
	 */
	static public void setLogging(boolean logging) {
		loggingEnabled = logging;
	}

	/**
	 * Retrieve the client instance connected to the DHT.
	 *
	 * @return the client
	 */
	public static ClientManager getClientInstance() {

		if (dhtClient == null || session == null) {
			establishConnection();
		}

		return dhtClient;
	}

	/**
	 * Retrieve the session instance associated with the connection to the DHT.
	 *
	 * @return the session
	 */
	public static Session getSessionInstance() {

		if (dhtClient == null || session == null) {
			establishConnection();
		}

		return session;
	}

	/**
	 * Get the URI used for the WebSocket connection to the DHT.
	 *
	 * @return the URI
	 */
	public static String getWebsocketUri() {
		return websocketUri;
	}

	/**
	 * Set the URI to use for the WebSocket connection to the DHT.
	 *
	 * @param websocketUri the desired URI
	 */
	public static void setWebsocketUri(String websocketUri) {
		DhtLogger.websocketUri = websocketUri;
	}

	/**
	 * Establish the connection to the DHT.
	 *
	 * @return if the connection was successfully established
	 */
	public static boolean establishConnection() {

		System.out.println("Connecting to DHT for logging");

		latch = new CountDownLatch(1000);
		dhtClient = ClientManager.createClient();
		try {
			// wss://socketsbay.com/wss/v2/2/demo/
			URI uri = new URI(websocketUri);
			session = dhtClient.connectToServer(DhtLogger.class, uri);
			// latch.await();
		} catch (DeploymentException | URISyntaxException | IOException e) {
			System.err.println("Error: Failed to connect to DHT for logging");
			e.printStackTrace();
			return false;
		}

		return true;
	}

	/**
	 * Establish the connection to the DHT.
	 *
	 * @param dhtWebsocketUri the URI to connect to the DHT using WebSocket
	 * @return if the connection was successfully established
	 */
	public static boolean establishConnection(String dhtWebsocketUri) {
		setWebsocketUri(dhtWebsocketUri);
		return establishConnection();
	}

	// DHT related methods

	@OnOpen
	public void onOpen(Session session) {
		System.out.println("--- Connected " + session.getId());

	}

	@OnMessage
	public String onMessage(String message, Session session) {
		// Do nothing for incoming messages from DHT
		return null;
	}

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		System.out.println("Session " + session.getId() + " closed because " + closeReason);
		latch.countDown();
	}

}