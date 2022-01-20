package se.sics.ace.ucs.properties;

import java.util.Map;

import it.cnr.iit.ucs.properties.components.RequestManagerProperties;

public class UcsRequestManagerProperties implements RequestManagerProperties {

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.requestmanager.RequestManager";
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
	public String getApiRemoteResponse() {
		return "/retrieveRemoteResponse";
	}

	@Override
	public boolean isActive() {
		return false;
	}

}
