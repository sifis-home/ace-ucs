package se.sics.ace.ucs.properties;

import java.util.Map;

import it.cnr.iit.ucs.properties.components.SessionManagerProperties;

public class UcsSessionManagerProperties implements SessionManagerProperties {

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.sessionmanager.SessionManager";
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
	public String getDbUri() {
		return "jdbc:sqlite:file::memory:?cache=shared";
	}

}
