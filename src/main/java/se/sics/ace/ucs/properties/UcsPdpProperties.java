package se.sics.ace.ucs.properties;

import java.util.Map;

import it.cnr.iit.ucs.properties.components.PdpProperties;

public class UcsPdpProperties implements PdpProperties {

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.pdp.PolicyDecisionPoint";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getId() {
		return "1";
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
		return null;
	}

}
