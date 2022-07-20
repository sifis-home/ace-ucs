package se.sics.ace.ucs;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
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
import it.cnr.iit.ucs.properties.components.PapProperties;
import it.cnr.iit.ucs.properties.components.PepProperties;
import it.cnr.iit.ucs.properties.components.PipProperties;
import it.cnr.iit.ucs.ucs.UCSInterface;
import it.cnr.iit.xacml.wrappers.PolicyWrapper;
import it.cnr.iit.xacml.wrappers.RequestWrapper;
import se.sics.ace.logging.PerformanceLogger;
import se.sics.ace.ucs.properties.AceUcsProperties;

/**
 *
 * @author Simone Facchini and Marco Rasori
 *
 */
public class UcsClient {

	private static final Logger LOGGER = Logger.getLogger(UcsClient.class.getName());

	private final AceUcsProperties properties;

	private UCSInterface ucs;

	private final String papPath;

	// for test purposes. Counts the number of times the tryAccess method has been invoked
	private int iterCounterTry = 0;
	// for test purposes. Counts the number of times the startAccess method has been invoked
	private int iterCounterStart = 0;

	public UcsClient(List<PipProperties> pipPropertiesList, PapProperties papProperties) {
		properties = new AceUcsProperties(pipPropertiesList, papProperties);
		try {
			ucs = new UCSCoreServiceBuilder().setProperties(properties).build();
		} catch (Exception e) {
			e.printStackTrace();
		}
		papPath = properties.getPolicyAdministrationPoint().getPath();
	}

	public TryAccessResponseMessage tryAccess(String request) {
		iterCounterTry++;
		TryAccessMessage message = buildTryAccessMessage(request);
		// log to file to record performance
		try {
			PerformanceLogger.getInstance().getLogger().log(Level.FINE,
					"t1T" + iterCounterTry + "         : " + new Date().getTime() + "\n");
		} catch (AssertionError e) {
			LOGGER.finest("Unable to record performance. PerformanceLogger not initialized");
		}
		TryAccessResponseMessage response = (TryAccessResponseMessage) ucs.tryAccess(message);
		// log to file to record performance
		try {
			PerformanceLogger.getInstance().getLogger().log(Level.FINE,
					"t2T" + iterCounterTry + "         : " + new Date().getTime() + "\n");
		} catch (AssertionError e) {
			LOGGER.finest("Unable to record performance. PerformanceLogger not initialized");
		}
		return response;
	}

	public StartAccessResponseMessage startAccess(String sessionId) {
		iterCounterStart++;
		StartAccessMessage message = buildStartAccessMessage(sessionId);
		try {
			PerformanceLogger.getInstance().getLogger().log(Level.FINE,
					"t1S" + iterCounterStart + "         : " + new Date().getTime() + "\n");
		} catch (AssertionError e) {
			LOGGER.finest("Unable to record performance. PerformanceLogger not initialized");
		}
		StartAccessResponseMessage response = (StartAccessResponseMessage) ucs.startAccess(message);
		try {
			PerformanceLogger.getInstance().getLogger().log(Level.FINE,
					"t2S" + iterCounterStart + "         : " + new Date().getTime() + "\n");
		} catch (AssertionError e) {
			LOGGER.finest("Unable to record performance. PerformanceLogger not initialized");
		}
		return response;
	}

	public EndAccessResponseMessage endAccess(String sessionId) {
		EndAccessMessage message = buildEndAccessMessage(sessionId);
		return (EndAccessResponseMessage) ucs.endAccess(message);
	}

	private TryAccessMessage buildTryAccessMessage(String request) {
		PepProperties pepProperties = properties.getPepList().get(0);
		TryAccessMessage message = new TryAccessMessage(pepProperties.getId(), pepProperties.getUri());
		message.setRequest(request);
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
