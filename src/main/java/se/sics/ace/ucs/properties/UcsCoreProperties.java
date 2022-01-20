package se.sics.ace.ucs.properties;

import java.util.HashMap;
import java.util.Map;

import it.cnr.iit.ucs.properties.components.CoreProperties;

public class UcsCoreProperties implements CoreProperties {

	@Override
	public String getUri() {
		return "http://localhost:9998";
	}

	@Override
	public String getJournalPath() {
		return "/tmp/ucf";
	}

	@Override
	public String getJournalProtocol() {
		return "file";
	}

	@Override
	public Map<String, String> getJournalAdditionalProperties() {
		return new HashMap<>();
	}

}
