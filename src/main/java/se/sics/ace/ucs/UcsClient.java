package se.sics.ace.ucs;

import java.util.Map;
import java.util.logging.Logger;

import it.cnr.iit.ucs.core.UCSCoreService;
import it.cnr.iit.ucs.core.UCSCoreServiceBuilder;
import it.cnr.iit.ucs.exceptions.RequestException;
import it.cnr.iit.ucs.message.endaccess.EndAccessMessage;
import it.cnr.iit.ucs.message.endaccess.EndAccessResponseMessage;
import it.cnr.iit.ucs.message.startaccess.StartAccessMessage;
import it.cnr.iit.ucs.message.startaccess.StartAccessResponseMessage;
import it.cnr.iit.ucs.message.tryaccess.TryAccessMessage;
import it.cnr.iit.ucs.message.tryaccess.TryAccessResponseMessage;
import it.cnr.iit.ucs.pap.PolicyAdministrationPoint;
import it.cnr.iit.ucs.pdp.PolicyDecisionPoint;
import it.cnr.iit.ucs.pep.PEPInterface;
import it.cnr.iit.ucs.properties.components.PepProperties;
import it.cnr.iit.ucs.ucs.UCSInterface;
import it.cnr.iit.xacml.wrappers.PolicyWrapper;
import it.cnr.iit.xacml.wrappers.RequestWrapper;
import se.sics.ace.ucs.properties.AceUcsProperties;

/**
 *
 * @author Simone Facchini and Marco Rasori
 *
 */
public class UcsClient {

	private static final Logger LOGGER = Logger.getLogger(UcsClient.class.getName());

//	private final String policyFileName = "standard_policy";

	private final AceUcsProperties properties;

	private UCSInterface ucs;

	private final String papPath;

	public UcsClient() {
		properties = new AceUcsProperties();
		try {
			ucs = new UCSCoreServiceBuilder().setProperties(properties).build();
		} catch (Exception e) {
			e.printStackTrace();
		}
		papPath = properties.getPolicyAdministrationPoint().getPath();
	}

	public TryAccessResponseMessage tryAccess(String request) {
		TryAccessMessage message = buildTryAccessMessage(request);
		return (TryAccessResponseMessage) ucs.tryAccess(message);
	}

	public StartAccessResponseMessage startAccess(String sessionId) {
		StartAccessMessage message = buildStartAccessMessage(sessionId);
		return (StartAccessResponseMessage) ucs.startAccess(message);
	}

	public EndAccessResponseMessage endAccess(String sessionId) {
		EndAccessMessage message = buildEndAccessMessage(sessionId);
		return (EndAccessResponseMessage) ucs.endAccess(message);
	}

	private TryAccessMessage buildTryAccessMessage(String request) {
		PepProperties pepProperties = properties.getPepList().get(0);
		TryAccessMessage message = new TryAccessMessage(pepProperties.getId(), pepProperties.getUri());
		message.setRequest(request);

//		ClassLoader classLoader = getClass().getClassLoader();
//		File file = new File(Objects.requireNonNull(classLoader.getResource(policyFileName)).getFile());
//		String policy = "";
//		try {
//			policy = new String(Files.readAllBytes(file.toPath()));
//		} catch (IOException e) {
//			log.severe("error reading policy file");
//			e.printStackTrace();
//		}
//		message.setPolicy(policy);

		return message;
	}

	private StartAccessMessage buildStartAccessMessage(String sessionId) {
		PepProperties pepProperties = properties.getPepList().get(0);
		StartAccessMessage message = new StartAccessMessage(pepProperties.getId(), pepProperties.getUri());
		message.setSessionId(sessionId);
		return message;
	}

	private EndAccessMessage buildEndAccessMessage(String sessionId) {
		PepProperties pepProperties = properties.getPepList().get(0);
		EndAccessMessage message = new EndAccessMessage(pepProperties.getId(), pepProperties.getUri());
		message.setSessionId(sessionId);
		return message;
	}

	public void addPolicy(String policy) {
		PolicyAdministrationPoint pap = new PolicyAdministrationPoint(properties.getPolicyAdministrationPoint());
		pap.addPolicy(policy);
	}

	public UCSInterface getInterface() {
		return ucs;
	}

	public AceUcsProperties getProperties() {
		return properties;
	}

	public Map<String, PEPInterface> getPepMap() {
		return ((UCSCoreService)ucs).getPEPMap();
	}

	public void setUcsHelperForPeps(UcsHelper uh){
		Map<String, PEPInterface> pepMap = getPepMap();
		for (Map.Entry<String, PEPInterface> entry : pepMap.entrySet()) {
			AcePep ap = (AcePep)(entry.getValue());
			ap.setUcsHelper(uh);
		}
	}

	public String findPolicy(String req) {
		RequestWrapper request;
		try{
			request = RequestWrapper.build(req);
		} catch(RequestException e) {
			LOGGER.info("Unable to create request wrapper");
			return null;
		}
		PolicyAdministrationPoint pap = new PolicyAdministrationPoint(properties.getPolicyAdministrationPoint());
		PolicyDecisionPoint pdp = new PolicyDecisionPoint(properties.getPolicyDecisionPoint());
		pdp.setPap(pap);
		PolicyWrapper policy = pdp.findPolicy(request);
		return policy.getPolicyType().getPolicyId();
	}

	public String getPapPath() {
		return papPath;
	}
}
