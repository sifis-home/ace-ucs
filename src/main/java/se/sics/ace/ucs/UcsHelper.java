package se.sics.ace.ucs;

import com.att.research.xacml.api.Request;
import it.cnr.iit.ucs.message.endaccess.EndAccessResponseMessage;
import it.cnr.iit.ucs.message.startaccess.StartAccessResponseMessage;
import it.cnr.iit.ucs.message.tryaccess.TryAccessResponseMessage;
import it.cnr.iit.ucs.properties.components.PapProperties;
import it.cnr.iit.ucs.properties.components.PipProperties;
import se.sics.ace.AceException;
import se.sics.ace.as.*;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.ucs.xacml.AdditionalAttribute;
import se.sics.ace.ucs.xacml.CATEGORY;
import se.sics.ace.ucs.xacml.RequestGenerator;
import se.sics.ace.ucs.xacml.RequestSerializationFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.*;
import java.util.*;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Simone Facchini and Marco Rasori
 *
 */
public class UcsHelper implements PDP, AutoCloseable {

	//TODO add the deleteAccess method.
	// This method is used to revoke the access of client cid to the audience rs with scope scope
	// <cid,rs,scope>
	// should:
	// 		1) terminate the session, if present
	// 		2) get the token identifier and revoke the access token
	// 		3) delete the policy file

	//TODO add the deleteAllAccess method.
	// This method is used to revoke the access of client cid to everything
	// <cid,*,*>
	// should:
	// 		1) terminate all the sessions that have subject-id==cid, if present
	// 		2) get the token identifiers and revoke the access tokens
	// 		3) delete the policy files

	//TODO add the deleteAllRsAccess method.
	// This method is used to revoke the access of client cid to everything concerning a given resource server rs
	// <cid,rs,*>
	// should:
	// 		1) terminate all the sessions that have subject-id==cid and resource-server==rs, if present
	// 		2) get the token identifiers and revoke the access tokens
	// 		3) delete the policy files
	// .
	// To implement these methods, we need to understand how to retrieve the policies that match
	// exactly the cid, the cid and the rs, or the cid, the rs, and the scope.

	private static final Logger LOGGER = Logger.getLogger(UcsHelper.class.getName());

	private final UcsClient ucs;

	private int policyIdCounter;

	private SQLConnector db = null;

	public static String tokenTable 			= "PdpToken";
	public static String introspectTable 		= "PdpIntrospect";
	public static String sessionTable 			= "PdpSessions";
	public static String introspectClaimsColumn = "claimsAccess";

	private PreparedStatement canToken;
	private PreparedStatement canIntrospect;

	private PreparedStatement addTokenAccess;
	private PreparedStatement addIntrospectAccess;

	private PreparedStatement insertSession;
	private PreparedStatement deleteSessions4Cti;
	private PreparedStatement updateCti;

	private PreparedStatement deleteTokenAccess;
	private PreparedStatement deleteIntrospectAccess;

	private PreparedStatement selectCti4Session;
	private PreparedStatement selectSessions4Cti;

	private PreparedStatement selectSession;

	private PreparedStatement selectAllSessions;
	private PreparedStatement deleteSession;
//	private PreparedStatement deleteAccess;
//	private PreparedStatement deleteAllAccess;
//	private PreparedStatement deleteAllRsAccess;

//	private PreparedStatement getAllAccess;

	private final Map<Integer, List<String>> pendingSessions;

	private RevocationHandler rh = null;

	private Token t = null;

	private final String basicPolicy;

	// for test purposes. Counts the number of times the canAccess method has been invoked
	private int iterCounter = 0;

	public UcsHelper(SQLConnector connection,
					 List<PipProperties> pipPropertiesList,
					 PapProperties papProperties) throws AceException {

		this.basicPolicy = readFileAsString(
				new File(Objects.requireNonNull(
						getClass().getClassLoader().getResource("policy-templates/policy_template"),
						"[ERROR] policy template file not found.").getFile()));

		LOGGER.setLevel(Level.SEVERE);

		initDatabase(connection);

		ucs = new UcsClient(pipPropertiesList, papProperties);
		ucs.setUcsHelperForPeps(this);

		this.pendingSessions = new HashMap<>();
	}

	/**
	 * Revoke a specific access right from a client by deleting the related policy.
	 * If a session is present with the provided parameters, delete it from the
	 * session table and revoke the related access token.
	 * Also, delete the other sessions related to the same access token from the
	 * session table.
	 *
	 * @param cid  the client identifier
	 * @param rid  the resource server identifier
	 * @param scope  the scope to be revoked
	 *
	 * @throws AceException if any parameter is null
	 */
	public void revokeAccess(String cid, String rid, String scope)
			throws AceException {
		if (cid == null || rid == null || scope == null) {
			throw new AceException(
					"revokeAccess() requires non-null parameters");
		}

		String request = getRequest(cid, rid, scope);
		String policyId = ucs.findPolicy(request);
		LOGGER.info("revokeAccess: found policy to delete. Policy ID = " + policyId);

		try {
			deletePolicyFile(policyId + ".xml");
		} catch(IOException e) {
			LOGGER.severe("Error deleting policy file: " + policyId + ".xml");
		}

		String sessionId = getSession(cid, rid, scope);
		if (sessionId != null) {
			revoke(sessionId);
		}
	}

	/**
	 * Delete a policy file from the folder containing the policies.
	 * The folder path is that of the policy administration point.
	 *
	 * @param fileName  name (with extension) of the file to be deleted
	 *
	 * @throws IOException if the deletion fails
	 */
	public void deletePolicyFile(String fileName) throws IOException {
		String policyFile = ucs.getPapPath() + fileName;

		//Delete policy file
		File pFile = new File(policyFile);
		if (!pFile.delete() && pFile.exists()) {
			throw new IOException("Failed to delete " + pFile);
		}
	}

	/**
	 * Get the session associated with the provided client identifier,
	 * resource server identifier, and scope
	 *
	 * @param cid  the client identifier
	 * @param rid  the resource server identifier
	 * @param scope  the scope
	 *
	 * @return the list of sessions associated with the token identifier
	 * @throws AceException throw AceException
	 */
	public synchronized String getSession(String cid, String rid, String scope) throws AceException {
		if (cid == null || rid == null || scope == null) {
			throw new AceException(
					"selectSession() requires non-null parameters");
		}
		try {
			this.selectSession.setString(1, cid);
			this.selectSession.setString(2, rid);
			this.selectSession.setString(3, scope);
			ResultSet result = this.selectSession.executeQuery();
			this.selectSession.clearParameters();
			if (result.next()) {
				String session = result.getString(DBConnector.sessionIdColumn);
				result.close();
				return session;
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return null;
	}

	public synchronized List<String> getAllSessions() throws AceException {
		List<String> sessions = new ArrayList<>();
		try {
			ResultSet result = this.selectAllSessions.executeQuery();
			this.selectAllSessions.clearParameters();
			while (result.next()) {
				sessions.add(result.getString(DBConnector.sessionIdColumn));
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return sessions;
	}

	/**
	 * Check if the client cid is allowed to access the audience aud with the scopes passed as argument.
	 * The method splits the scopes and create a xml request for each scope.
	 * Then, for each scope, it executes the UCS methods tryAccess and startAccess.
	 * If both methods return permit, a session is created by the UCS session manager and an entry containing
	 * the session identifier is added to the database.
	 * The entry has fields: < sessionId, cid, rid, scope, cti >.
	 * cti is set to null and will be updated later with the method updateSessionsWithCti.
	 *
	 * @param cid  the identifier of the client to be allowed access
	 * @param aud  		the audience
	 * @param scopes  	the identifier of the scope for which access is allowed
	 *
	 * @throws AceException throws ace exception
	 */
	@Override
	public String canAccess(String cid, Set<String> aud, Object scopes, int evaluationId) throws AceException {
		if (evaluationId < 0)
			throw new AceException("evaluationId cannot be negative " +
					"for a PDP supporting revocation");

		if (cid == null || aud == null || scopes == null) {
			throw new AceException(
					"canAccess() requires non-null parameters");
		}

		iterCounter++;

		String scopeStr;
		if (scopes instanceof String) {
			scopeStr = (String) scopes;
		} else {
			throw new AceException("non-String scopes are not supported");
		}

		String[] scopeArray = scopeStr.split(" ");
		if (scopeArray.length <= 0) {
			return null;
		}

		Set<String> rss = new HashSet<>();
		for (String audE : aud) {
			rss.addAll(this.db.getRSS(audE));
		}
		if (rss.isEmpty()) {
			return null;
		}
		if (rss.size() > 1) {
			LOGGER.severe("Audience multi server not implemented. \n"
					+ "    Taking one of the resource servers at random...");
		}

		// if we have more than one rs, we choose just one at random because
		// audience multi server is not implemented
		String rid = null;
		for (String str : rss) rid = str;

		List<String> xacmlRequests = getRequestsListPerScope(cid, rid, scopeArray);
		StringBuilder allowedScopes = new StringBuilder();
		int count = 0;
		List<String> allowedSessions = new ArrayList<>();

		for (String req : xacmlRequests) {
			// if both tryAccess and startAccess return PERMIT, add the entry to the database.
			// The entry contains <sessionId, clientId, rsId, scope, cti>
			// cti is set to null as it will be created later by the token endpoint.

			LOGGER.finest("performing tryAccess, request = " + req);
			TryAccessResponseMessage tryResponse = ucs.tryAccess(req);

			if (tryResponse.getEvaluation() != null && tryResponse.getEvaluation().getResult().equalsIgnoreCase("permit")) {
				LOGGER.info("tryAccess complete with " +
						tryResponse.getEvaluation().getResult() +
						" for subscope '" + scopeArray[count] + "'\n" );
				LOGGER.finest("tryAccess response = " + tryResponse.getEvaluation().getResponse());

				String sessionId = tryResponse.getSessionId();
				StartAccessResponseMessage startResponse = ucs.startAccess(sessionId);
				LOGGER.finest("startAccess response = " + startResponse.getEvaluation().getResponse());

				if (startResponse.getEvaluation().getResult().equalsIgnoreCase("permit")) {
					LOGGER.info("startAccess complete with " +
							startResponse.getEvaluation().getResult() +
									" for subscope '" + scopeArray[count] + "'\n" );

					allowedScopes.append(scopeArray[count]).append(" ");
					allowedSessions.add(sessionId);

					// add the session to the sessions table
					addSession(sessionId, cid, rid, scopeArray[count], null);
				}
				else {
					LOGGER.severe("startAccess complete with " +
							startResponse.getEvaluation().getResult() +
							" for subscope '" + scopeArray[count] + "'\n" );
				}
			}
			else {
				LOGGER.severe("tryAccess complete with " +
						tryResponse.getEvaluation().getResult() +
						" for subscope '" + scopeArray[count] + "'\n" );
			}
			count++;
		}

		if (allowedScopes.toString().equals("")){
			LOGGER.info("canAccess results: No scopes allowed");
			return null;
		}

		allowedScopes.deleteCharAt(allowedScopes.toString().length()-1);
		LOGGER.severe("canAccess results: allowed scopes = " + allowedScopes);
		this.pendingSessions.put(evaluationId, allowedSessions);

		return allowedScopes.toString();
	}

	/**
	 * Check allowance to ask access tokens to the token endpoint.
	 *
	 * @param id the identifier of the entity to be allowed access
	 *
	 * @throws AceException	throws ace exception
	 */
	@Override
	public boolean canAccessToken(String id) throws AceException {
		if (id == null) {
			throw new AceException("canAccessToken() requires non-null identifier");
		}
		try {
			this.canToken.setString(1, id);
			ResultSet result = this.canToken.executeQuery();
			this.canToken.clearParameters();
			if (result.next()) {
				result.close();
				return true;
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return false;
	}

	/**
	 * Add access permission for the token endpoint
	 *
	 * @param id the identifier of the entity to be allowed access
	 *
	 * @throws AceException	throws ace exception
	 */
	public void addTokenAccess(String id) throws AceException {
		if (id == null) {
			throw new AceException("addTokenAccess() requires non-null identifier");
		}
		try {
			this.addTokenAccess.setString(1, id);
			this.addTokenAccess.execute();
			this.addTokenAccess.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Add access permission for the introspect endpoint, defaulting to access to activeness and claims.
	 *
	 * @param id the identifier of the entity to be allowed access
	 *
	 * @throws AceException	throws ace exception
	 */
	public void addIntrospectAccess(String id) throws AceException {
		addIntrospectAccess(id, IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
	}


	/**
	 * Add access permission for the introspect endpoint
	 *
	 * @param id          the identifier of the entity to be allowed access
	 * @param accessLevel the level of access to give when introspecting
	 *
	 * @throws AceException	throws ace exception
	 */
	public void addIntrospectAccess(String id, IntrospectAccessLevel accessLevel) throws AceException {
		if (id == null) {
			throw new AceException(
					"addIntrospectAccess() requires non-null identifier");
		}
		if (accessLevel.equals(IntrospectAccessLevel.NONE)) {
			throw new AceException(
					"addIntrospectAccess() requires non-NONE access level");
		}
		try {
			boolean hasClaimsAccess = accessLevel.equals(IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
			this.addIntrospectAccess.setString(1, id);
			this.addIntrospectAccess.setBoolean(2, hasClaimsAccess);
			this.addIntrospectAccess.execute();
			this.addIntrospectAccess.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}


	@Override
	public IntrospectAccessLevel getIntrospectAccessLevel(String rid) throws AceException {
		if (rid == null) {
			throw new AceException(
					"getIntrospectAccessLevel() requires non-null identifier");
		}
		try {
			this.canIntrospect.setString(1, rid);
			ResultSet result = this.canIntrospect.executeQuery();
			this.canIntrospect.clearParameters();
			if (result.next()) {
				boolean canAccessClaims = result.getBoolean(introspectClaimsColumn);
				result.close();
				if (canAccessClaims) {
					return IntrospectAccessLevel.ACTIVE_AND_CLAIMS;
				}
				return IntrospectAccessLevel.ACTIVE_ONLY;
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return IntrospectAccessLevel.NONE;
	}


	/**
	 * Add access permission for a client:
	 * Creates a xml file containing a XACML policy from a template.
	 * It substitutes placeholder fields with those passed as arguments to this method
	 *
	 * @param cid   client identifier
	 * @param rid   resource server identifier
	 * @param scope scopes requested, e.g., "r_light", "co2"
	 *
	 * @throws AceException ace exception
	 */
	public void addAccess(String cid, String rid, String scope) throws AceException {

		String policy = new String(this.basicPolicy);

		policy = policy.replaceAll("SUBJECT_HERE", cid)
					   .replaceAll("RESOURCE_HERE", scope)
				       .replaceAll("RESOURCESERVER_HERE", rid)
				       .replaceAll("POLICYID_HERE", ("policy_" + policyIdCounter));
		ucs.addPolicy(policy);

		policyIdCounter++;
	}


	/**
	 * Add access permission for a client:
	 * Creates a xml file containing a XACML policy from a template.
	 * It substitutes placeholder fields with those passed as arguments to this method
	 *
	 * @param cid   client identifier
	 * @param rid   resource server identifier
	 * @param scope scopes requested, e.g., "r_light", "co2"
	 * @param templateFile  the file to be used as a template for creating the access policy
	 *
	 * @throws AceException ace exception
	 */
	public void addAccess(String cid, String rid, String scope, String templateFile) throws AceException {
		String policy = readFileAsString(
				new File(templateFile));

		policy = policy.replaceAll("SUBJECT_HERE", cid)
				.replaceAll("RESOURCE_HERE", scope)
				.replaceAll("RESOURCESERVER_HERE", rid)
				.replaceAll("POLICYID_HERE", ("policy_" + policyIdCounter));
		ucs.addPolicy(policy);

		policyIdCounter++;
	}


	/**
	 * Add access permission for a client given an XACML policy
	 *
	 */
	public void addAccessFromFile(String policy) {
		ucs.addPolicy(policy);
	}

	/**
	 * Obtain a list of XACML requests, one for each scope
	 *
	 * @param scopeArray  String array of requested scopes
	 * @param cid  the identifier of the entity that requests access
	 * @param rid  the identifier of the RS to which the request is addressed
	 */
	private List<String> getRequestsListPerScope(String cid, String rid, String[] scopeArray) {
		List<String> requests = new ArrayList<>();
		for (String scope : scopeArray) {
			String xacmlRequest = getRequest(cid, rid, scope);
			requests.add(xacmlRequest);
		}
		return requests;
	}

	/**
	 * Obtain an XACML request, built on the provided client identifier,
	 * resource server identifier, and scope
	 *
	 * @param cid  the identifier of the entity that requests access
	 * @param rid  the identifier of the RS to which the request is addressed
	 * @param scope  the requested scope
	 *
	 * @return a string containing the xacml request
	 */
	public String getRequest(String cid, String rid, String scope) {
		AdditionalAttribute rsAttr = new AdditionalAttribute(CATEGORY.RESOURCE,
				"urn:oasis:names:tc:xacml:1.0:resource:resource-server", rid,
				"http://www.w3.org/2001/XMLSchema#string");

		Request request = new RequestGenerator().createXACMLV3Request(
				cid, scope, "read", true, rsAttr);

		// return xacml request
		return RequestSerializationFactory.newInstance().serialize(request,
				RequestSerializationFactory.SERIALIZATION_FORMAT.XML);
	}

	/**
	 * Put the content of a file into a string
	 *
	 * @param file the file to use
	 *
	 * @return the string with the file content
	 */
	private String readFileAsString(File file) {
		String res = null;
		try {
			res = new String(Files.readAllBytes(file.toPath()));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	/**
	 * Revoke an access right to the Token endpoint
	 *
	 * @param id  the identifier if the entity for which access is revoked
	 *
	 * @throws AceException throws ace exception
	 */
	public void revokeTokenAccess(String id) throws AceException {
		if (id == null) {
			throw new AceException(
					"revokeTokenAccess() requires non-null identifier");
		}
		try {
			this.deleteTokenAccess.setString(1, id);
			this.deleteTokenAccess.execute();
			this.deleteTokenAccess.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Revoke an access right to the Introspect endpoint.
	 *
	 * @param id  the identifier of the entity for which access is revoked
	 *
	 * @throws AceException throws ace exception
	 */
	public void revokeIntrospectAccess(String id) throws AceException {
		if (id == null) {
			throw new AceException(
					"revokeIntrospectAccess() requires non-null id");
		}
		try {
			this.deleteIntrospectAccess.setString(1, id);
			this.deleteIntrospectAccess.execute();
			this.deleteIntrospectAccess.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}


	/**
	 *  Associate the pending sessions (identified by evaluationId) with the token identifier
	 *
	 * @param cti the token identifier
	 * @param evaluationId value that links the pending sessions to the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	@Override
	public void updateSessionsWithCti(String cti, int evaluationId) throws AceException{
		if (evaluationId < 0)
			throw new AceException("evaluationId cannot be negative " +
					"for a PDP supporting revocation");

		// use the evaluationId within the map to retrieve the sessions.
		// add the token identifier to the matching sessions in the table
		List<String> sessionsList = this.pendingSessions.get(evaluationId);

		for (String sessionId : sessionsList) {
			try {
				this.updateCti.setString(1, cti);
				this.updateCti.setString(2, sessionId);
				this.updateCti.execute();
				this.updateCti.clearParameters();

			} catch (SQLException e) {
				throw new AceException(e.getMessage());
			}
		}
		this.pendingSessions.remove(evaluationId);
	}

	/**
	 * Delete sessions from both the pending sessions and the UCS session manager
	 * Rollback method called by the /token when it cannot finalize issuing
	 * of an access token, but the canAccess method was already executed
	 *
	 * @param evaluationId identifier to retrieve the sessions
	 *
	 * @throws AceException throw AceException
	 */
	@Override
	public void terminatePendingSessions(int evaluationId) throws AceException {
		if (evaluationId < 0) {
			throw new AceException("Unable to remove pending sessions: " +
					"evaluationId cannot be negative for a PDP supporting revocation");
		}

		List<String> sessionsList = this.pendingSessions.get(evaluationId);
		// call the endAccess on all the sessions in sessionsList
		terminateSessions(sessionsList);

		this.purgeSessions(sessionsList);

		this.pendingSessions.remove(evaluationId);
	}

	/**
	 * Terminate with endAccess() all on the sessions passed as input
	 *
	 * @param sessionsList list of session identifiers of the sessions to terminate
	 */
	public void terminateSessions(List<String> sessionsList) {
		for (String sessionId : sessionsList) {
			EndAccessResponseMessage endResponse = ucs.endAccess(sessionId);
			LOGGER.finest("endAccess response = " + endResponse.getEvaluation().getResponse());
			if (endResponse.getEvaluation().getResult().equalsIgnoreCase("permit")) {
				LOGGER.info("endAccess complete with PERMIT");
			}
			else {
				LOGGER.severe("endAccess complete with DENY");
			}
		}
	}

	/**
	 * Delete a specific session from the session table
	 *
	 * @param sessionId the session identifier
	 *
	 * @throws AceException throw AceException
	 */
	public synchronized void purgeSession(String sessionId) throws AceException {
		if (sessionId == null) {
			throw new AceException("purgeSession() requires non-null sessionId");
		}
		try {
			this.deleteSession.setString(1, sessionId);
			this.deleteSession.execute();
			this.deleteSession.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Delete sessions from the session table
	 *
	 * @param sessions the list of session identifiers
	 *
	 * @throws AceException throw AceException
	 */
	public void purgeSessions(List<String> sessions) throws AceException{
		try {
			for (String sessionId : sessions) {
				purgeSession(sessionId);
			}
		} catch (AceException e) {
			LOGGER.severe("Unable to delete session from sessionTable");
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Get the token identifier associated with the session.
	 *
	 * @param sessionId the session identifier
	 * @return the token identifier
	 * @throws AceException throw AceException
	 */
	public synchronized String getCti4Session(String sessionId) throws AceException {
		if (sessionId == null || sessionId.isEmpty()) {
			throw new AceException(
					"getCti4Session() requires non-null, non-empty sessionId");
		}
		try {
			this.selectCti4Session.setString(1, sessionId);
			ResultSet result = this.selectCti4Session.executeQuery();
			this.selectCti4Session.clearParameters();
			if (result.next()) {
				String cti = result.getString(DBConnector.ctiColumn);
				result.close();
				return cti;
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return null;
	}

	/**
	 * Delete from the session table the entries that match
	 * the given token identifier
	 *
	 * @param cti the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	public synchronized void purgeSessions4Cti(String cti) throws AceException {
		if (cti == null) {
			throw new AceException("purgeSessions4Cti() requires non-null cti");
		}
		try {
			this.deleteSessions4Cti.setString(1, cti);
			this.deleteSessions4Cti.execute();
			this.deleteSessions4Cti.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Get the token identifier associated with the provided
	 * session identifier and revoke the token using the
	 * token identifier
	 *
	 * @param sessionId the session identifier
	 *
	 * @throws AceException throw AceException
	 */
	public void revoke(String sessionId) throws AceException {

		// get cti for the given sessionId
		String cti = getCti4Session(sessionId);

		// revoke the token
		revokeToken(cti);

		// remove the token from the database and the related
		// quantities from the token endpoint
		t.removeToken(cti);

		// terminate all the sessions associated with cti and
		// purge them from the session table
		removeSessions4Cti(cti);
	}

	/**
	 * Terminate with endAccess() all the sessions associated
	 * with the given token identifier.
	 * Also, delete the matching entries from the session table.
	 *
	 * @param cti the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	@Override
	public void removeSessions4Cti(String cti) throws AceException {
		// call the endAccess on all the sessions associated with cti
		terminateSessions4Cti(cti);

		// remove entries from session table
		purgeSessions4Cti(cti);
	}

	/**
	 * Revoke a token
	 *
	 * @param cti the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	@Override
	public void revokeToken(String cti) throws AceException {
		if (this.rh != null) {
			this.rh.revoke(cti);
		}
		else {
			LOGGER.info("RevocationHandler not initialized: " +
					"Token will not be placed in the trlTable, " +
					"and trl-related procedures will be not executed.");
		}
	}

	/**
	 * Get all the sessions associated with the token identifier
	 * and terminate them through endAccess
	 *
	 * @param cti the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	public void terminateSessions4Cti(String cti) throws AceException {
		// get the sessions associated with the provided
		// token identifier from the session table, and call
		// the endAccess(sessionId) on each.

		List<String> sessions = getSessions4Cti(cti);
		terminateSessions(sessions);
	}

	/**
	 * Get the list of sessions associated with the token identifier
	 *
	 * @param cti the token identifier
	 * @return the list of sessions associated with the token identifier
	 * @throws AceException throw AceException
	 */
	public synchronized List<String> getSessions4Cti(String cti) throws AceException {
		if (cti == null || cti.isEmpty()) {
			throw new AceException(
					"getSessions4Cti() requires non-null, non-empty cti");
		}
		List<String> sessions = new ArrayList<>();
		try {
			this.selectSessions4Cti.setString(1, cti);
			ResultSet result = this.selectSessions4Cti.executeQuery();
			this.selectSessions4Cti.clearParameters();
			while (result.next()) {
				sessions.add(result.getString(DBConnector.sessionIdColumn));
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return sessions;
	}

	/**
	 * Insert an entry in the session table
	 *
	 * @param sessionId the session identifier
	 * @param clientId the client identifier
	 * @param rs the resource server identifier
	 * @param scope the scope
	 * @param cti the token identifier
	 *
	 * @throws AceException throw AceException
	 */
	public synchronized void addSession(String sessionId, String clientId,
			String rs, String scope, String cti)
				throws AceException {
		if (sessionId == null || sessionId.isEmpty()) {
			throw new AceException(
					"addSession() requires non-null, non-empty sessionId");
		}
		if (clientId == null || clientId.isEmpty()) {
			throw new AceException(
					"addSession() requires non-null, non-empty clientId");
		}
		if (rs == null || rs.isEmpty()) {
			throw new AceException(
					"addSession() requires non-null, non-empty rs");
		}
		if (scope == null || scope.isEmpty()) {
			throw new AceException(
					"addSession() requires non-null, non-empty scope");
		}

		try {
			this.insertSession.setString(1, sessionId);
			this.insertSession.setString(2, clientId);
			this.insertSession.setString(3, rs);
			this.insertSession.setString(4, scope);
			this.insertSession.setString(5, cti);
			this.insertSession.execute();
			this.insertSession.clearParameters();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
	}

	/**
	 * Initialize the database. Create the tables and define
	 * prepared statements to query the database.
	 *
	 * @param connection the database connector
	 *
	 * @throws AceException throws ace exception
	 */
	private void initDatabase(SQLConnector connection) throws AceException {
		this.db = connection;

		String createTokenTable = this.db.getAdapter()
				.updateEngineSpecificSQL("CREATE TABLE IF NOT EXISTS "
						+ tokenTable+ "("
						+ DBConnector.idColumn + " varchar(255) NOT NULL);");

		String createIntrospectTable = this.db.getAdapter()
				.updateEngineSpecificSQL("CREATE TABLE IF NOT EXISTS "
						+ introspectTable + "("
						+ DBConnector.idColumn + " varchar(255) NOT NULL,"
						+ introspectClaimsColumn + " boolean NOT NULL);");

		String createSessionTable = this.db.getAdapter()
				.updateEngineSpecificSQL("CREATE TABLE IF NOT EXISTS "
						+ sessionTable + "("
						+ DBConnector.sessionIdColumn + " varchar(255) NOT NULL,"
						+ DBConnector.clientIdColumn + " varchar(255) NOT NULL,"
						+ DBConnector.rsIdColumn + " varchar(255) NOT NULL,"
						+ DBConnector.scopeColumn + " varchar(255) NOT NULL,"
						+ DBConnector.ctiColumn + " varchar(255));");

		try (Connection conn = this.db.getAdapter().getDBConnection(); Statement stmt = conn.createStatement()) {
			stmt.execute(createTokenTable);
			stmt.execute(createIntrospectTable);
			stmt.execute(createSessionTable);
		} catch (SQLException e) {
			e.printStackTrace();
			throw new AceException(e.getMessage());
		}

		this.canToken = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
						+ tokenTable
						+ " WHERE " + DBConnector.idColumn + "=?;"));

		this.canIntrospect = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
						+ introspectTable +
						" WHERE " + DBConnector.idColumn + "=?;"));

		this.addTokenAccess = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
						+ tokenTable + " VALUES (?);"));

		this.addIntrospectAccess = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
						+ introspectTable + " VALUES (?,?);"));

		this.insertSession = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
						+ sessionTable + " VALUES (?,?,?,?,?);"));

		this.deleteSessions4Cti = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
						+ sessionTable
						+ " WHERE " + DBConnector.ctiColumn + "=?;"));

		this.updateCti = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("UPDATE "
						+ sessionTable
						+ " SET " + DBConnector.ctiColumn + " = ?"
						+ " WHERE " + DBConnector.sessionIdColumn + " = ?;"));

		this.deleteTokenAccess = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
						+ tokenTable
						+ " WHERE " + DBConnector.idColumn + "=?;"));

		this.deleteIntrospectAccess = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
						+ introspectTable
						+ " WHERE " + DBConnector.idColumn + "=?;"));

		this.selectCti4Session = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT "
						+ DBConnector.ctiColumn + " FROM "
						+ sessionTable
						+ " WHERE " + DBConnector.sessionIdColumn + "=?;"));

		this.selectSessions4Cti = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT "
						+ DBConnector.sessionIdColumn + " FROM "
						+ sessionTable
						+ " WHERE " + DBConnector.ctiColumn + "=?;"));

		this.selectSession = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT "
						+ DBConnector.sessionIdColumn + " FROM "
						+ sessionTable
						+ " WHERE (" + DBConnector.clientIdColumn + "=?)"
						+ " AND (" + DBConnector.rsIdColumn + "=?)"
						+ " AND (" + DBConnector.scopeColumn + "=?);"));

		this.selectAllSessions = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("SELECT "
						+ DBConnector.sessionIdColumn + " FROM "
						+ sessionTable
						+ ";"));

		this.deleteSession = this.db.prepareStatement(
				this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
						+ sessionTable
						+ " WHERE " + DBConnector.sessionIdColumn + "=?;"));


/*		this.deleteAccess = this.db.prepareStatement(this.db.getAdapter()
				.updateEngineSpecificSQL("DELETE FROM " + accessTable + " WHERE " + DBConnector.idColumn + "=?"
						+ " AND " + DBConnector.rsIdColumn + "=?" + " AND " + DBConnector.scopeColumn + "=?;"));

		this.deleteAllAccess = this.db.prepareStatement(this.db.getAdapter()
				.updateEngineSpecificSQL("DELETE FROM " + accessTable + " WHERE " + DBConnector.idColumn + "=?;"));

		this.deleteAllRsAccess = this.db.prepareStatement(this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
				+ accessTable + " WHERE " + DBConnector.idColumn + "=?" + " AND " + DBConnector.rsIdColumn + "=?;"));

		this.getAllAccess = this.db.prepareStatement(this.db.getAdapter()
				.updateEngineSpecificSQL("SELECT * FROM " + accessTable + " WHERE " + DBConnector.idColumn + "=?;"));
*/
	}

	/**
	 * Close the connection with the database and delete all the
	 * policy files
	 *
	 * @throws Exception throws exception
	 */
	@Override
	public void close() throws Exception {

		terminateSessions(getAllSessions());

		this.db.close();

		// delete all files in the policy folder
		for(File file: Objects.requireNonNull(new File(ucs.getPapPath()).listFiles()))
			if (!file.isDirectory() && file.getName().endsWith(".xml"))
				deletePolicyFile(file.getName());
	}

	/**
	 * Set the RevocationHandler
	 */
	@Override
	public void setRevocationHandler(RevocationHandler rh) {
		this.rh = rh;
	}

	/**
	 * Set the token endpoint
	 */
	@Override
	public void setTokenEndpoint(Token t) {
		this.t = t;
	}

}