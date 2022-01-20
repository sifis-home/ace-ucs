package se.sics.ace.ucs.properties;

import java.util.Map;

import it.cnr.iit.ucs.properties.components.ContextHandlerProperties;

public class UcsCHProperties implements ContextHandlerProperties {

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.contexthandler.ContextHandler";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
		return null;
	}

	@Override
	public String getId() {
		return "1";
	}

	@Override
	public String getUri() {
		return "http://localhost:9998";
	}

}
