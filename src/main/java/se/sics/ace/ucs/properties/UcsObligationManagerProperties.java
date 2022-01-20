package se.sics.ace.ucs.properties;

import java.util.Map;

import it.cnr.iit.ucs.properties.components.ObligationManagerProperties;

public class UcsObligationManagerProperties implements ObligationManagerProperties {

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.obligationmanager.ObligationManager";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
		return null;
	}

	@Override
	public String getId() {
		return "1";
	}

}
