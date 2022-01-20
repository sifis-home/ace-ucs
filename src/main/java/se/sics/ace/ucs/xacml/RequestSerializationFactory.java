package se.sics.ace.ucs.xacml;

import com.att.research.xacml.api.Request;
import com.att.research.xacml.std.json.JSONRequest;
import com.att.research.xacml.std.json.JSONStructureException;

import java.util.logging.Logger;

public class RequestSerializationFactory {

	private static final Logger LOGGER = Logger.getLogger(RequestGenerator.class.getName());
	private static final RequestSerializationFactory instance = new RequestSerializationFactory();
	private RequestXMLSerializer serializer = new RequestXMLSerializer();

	public enum SERIALIZATION_FORMAT {
		XML, JSON
	}

	protected RequestSerializationFactory() {
	}

	public static RequestSerializationFactory newInstance() {
		return instance;
	}

	public String serialize(Request request, SERIALIZATION_FORMAT format) {
		try {
			switch (format) {
			case JSON:
				return JSONRequest.toString(request);
			case XML:
				return serializer.serialize(request);
			}
		} catch (Exception e) {
			LOGGER.severe(e.getClass().getSimpleName() + " : " + e.getMessage());
		}
		return null;
	}

	public Request unserialize(String request, SERIALIZATION_FORMAT format) {
		try {
			switch (format) {
			case JSON:
				return JSONRequest.load(request);
			case XML:
				return serializer.unserialize(request);
			}
		} catch (JSONStructureException e) {
			LOGGER.severe(e.getClass().getSimpleName() + " : " + e.getMessage());
		}
		return null;
	}
}
