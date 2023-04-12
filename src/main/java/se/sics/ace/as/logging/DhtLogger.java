package se.sics.ace.as.logging;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.CountDownLatch;

import com.google.gson.GsonBuilder;
import org.glassfish.tyrus.client.ClientManager;

import com.google.gson.Gson;

import jakarta.websocket.ClientEndpoint;
import jakarta.websocket.CloseReason;
import jakarta.websocket.DeploymentException;
import jakarta.websocket.OnClose;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;

/*
 * Log message format:
{
   "RequestPostTopicUUID":{
      "topic_name":"SIFIS:Logs",
      "topic_uuid":"Logs",
      "value":{
         "logs":{
            "message":"Returning token. ctiStr: cnMyMA\u003d\u003d. rsName: rs2. audStr: rs2. id: Server1",
            "priority":1,
            "severity":0,
            "category":"ACE Authorization Server"
         }
      }
   }
}
*/

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

	private static String LOG_TOPIC_NAME = "SIFIS:Logs";
	private static String LOG_TOPIC_UUID = "Logs";

	/**
	 * Sends a logging message to the DHT
	 * 
	 * @param message the message
	 * @param priority the priority
	 * @param severity the severity
	 * @param category the category
	 */
	static public void sendLog(String message, int priority, int severity, String category) {

		// Return if DHT logging is not used
		if (!loggingEnabled) {
			return;
		}

		// If a connection is not established yet (which should
		// have been done from the application), do it now
		boolean dhtConnected = true;
		if (dhtClient == null || session == null) {
			dhtConnected = establishConnection();
		}

		// If the connection failed to be established, do nothing
		if (!dhtConnected) {
			return;
		}

		// Build the outgoing JSON payload for the DHT
		JsonOut outgoing = new JsonOut();

		RequestPostTopicUUID requestVal = new RequestPostTopicUUID();
		OutValue valueVal = new OutValue();
		Logs logsVal = new Logs();

		requestVal.setTopicName(LOG_TOPIC_NAME);
		requestVal.setTopicUuid(LOG_TOPIC_UUID);

		logsVal.setMessage(message);
		logsVal.setPriority(priority);
		logsVal.setSeverity(severity);
		logsVal.setCategory(category);

		valueVal.setLogs(logsVal);
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

	// {"Command":{"value":{"logs":{"message":"error","priority":1,"severity":5,"category":"AS"}}}}
	static public void main(String[] args) {

		// Build outgoing JSON to DHT
		JsonOut outgoing = new JsonOut();

		RequestPostTopicUUID commandVal = new RequestPostTopicUUID();
		OutValue valueVal = new OutValue();
		Logs logsVal = new Logs();

		logsVal.setMessage("Error");
		logsVal.setPriority(10);
		logsVal.setSeverity(4);
		logsVal.setCategory("AS");

		valueVal.setLogs(logsVal);
		commandVal.setValue(valueVal);
		outgoing.setPayload(commandVal);

		Gson gsonOut = new GsonBuilder().disableHtmlEscaping().create();
		String jsonOut = gsonOut.toJson(outgoing);
		System.out.println("AAAAAAAAAAA " + jsonOut);
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
			URI uri = new URI("ws://localhost:3000/ws");
			session = dhtClient.connectToServer(DhtLogger.class, uri);
			// latch.await();
		} catch (DeploymentException | URISyntaxException | IOException e) {
			System.out.println("Error: Failed to connect to DHT for logging");
			System.out.println(e.getMessage());
			//e.printStackTrace();
			return false;
		}

		return true;
	}

	// DHT related methods

	@OnOpen
	public void onOpen(Session session) {
		System.out.println("--- Connected " + session.getId());
		// try {
		// session.getBasicRemote().sendText("start");
		// } catch (IOException e) {
		// throw new RuntimeException(e);
		// }
	}

	@OnMessage
	public String onMessage(String message, Session session) {
		return null;
	}

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		System.out.println("Session " + session.getId() + " closed because " + closeReason);
		latch.countDown();
	}

}
