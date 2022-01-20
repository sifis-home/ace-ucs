package se.sics.ace.ucs.properties;

import java.util.ArrayList;
import java.util.List;

import it.cnr.iit.ucs.properties.UCSProperties;
import it.cnr.iit.ucs.properties.components.ContextHandlerProperties;
import it.cnr.iit.ucs.properties.components.CoreProperties;
import it.cnr.iit.ucs.properties.components.ObligationManagerProperties;
import it.cnr.iit.ucs.properties.components.PapProperties;
import it.cnr.iit.ucs.properties.components.PdpProperties;
import it.cnr.iit.ucs.properties.components.PepProperties;
import it.cnr.iit.ucs.properties.components.PipProperties;
import it.cnr.iit.ucs.properties.components.RequestManagerProperties;
import it.cnr.iit.ucs.properties.components.SessionManagerProperties;

public class AceUcsProperties implements UCSProperties {

	@Override
	public CoreProperties getCore() {
		return new UcsCoreProperties();
	}

	@Override
	public ContextHandlerProperties getContextHandler() {
		return new UcsCHProperties();
	}

	@Override
	public RequestManagerProperties getRequestManager() {
		return new UcsRequestManagerProperties();
	}

	@Override
	public SessionManagerProperties getSessionManager() {
		return new UcsSessionManagerProperties();
	}

	@Override
	public PdpProperties getPolicyDecisionPoint() {
		return new UcsPdpProperties();
	}

	@Override
	public PapProperties getPolicyAdministrationPoint() {
		return new UcsPapProperties();
	}

	@Override
	public ObligationManagerProperties getObligationManager() {
		return new UcsObligationManagerProperties();
	}

	@Override
	public List<PipProperties> getPipList() {
		List<PipProperties> res = new ArrayList<>();
		res.add(new UcsPipProperties());
		return res;
	}
	@Override
	public List<PepProperties> getPepList() {
		List<PepProperties> res = new ArrayList<>();
		res.add(new UcsPepProperties());
		return res;
	}

}

