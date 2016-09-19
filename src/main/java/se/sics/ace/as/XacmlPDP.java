package se.sics.ace.as;

import java.io.File;
import java.io.FilenameFilter;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.wso2.balana.PDPConfig;
import org.wso2.balana.attr.StringAttribute;
import org.wso2.balana.ctx.AbstractResult;
import org.wso2.balana.ctx.Attribute;
import org.wso2.balana.ctx.ResponseCtx;
import org.wso2.balana.ctx.xacml3.RequestCtx;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.wso2.balana.xacml3.Attributes;

/**
 * A PDP that uses XACML to provide access control decisions.
 * 
 * @author Ludwig Seitz
 *
 */
public class XacmlPDP implements PDP {

	private org.wso2.balana.PDP pdp;
	
	/**
	 * The standard URI for listing a subject's id
	 */
	private static URI SUBJECT_ID =
		URI.create("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
	
	/**
     * The standard URI for listing a resource's id
     */
    private static final URI RESOURCE_ID =
        URI.create("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
    
	/**
	 * The standard URI for the subject category
	 */
	private static URI SUBJECT_CAT =
		URI.create("urn:oasis:names:tc:xacml:1.0:subject-category:"
				+ "access-subject");

	/**
     * The standard URI for the resource category
     */
    private static final URI RESOURCE_CAT =
        URI.create("urn:oasis:names:tc:xacml:3.0:attribute-category:resource");
    
	/**
     * The standard URI for the action category
     */
    private static final URI ACTION_CAT =
        URI.create("urn:oasis:names:tc:xacml:3.0:attribute-category:action");
    
    /**
     * The resource identifier for the token endpoint
     */
    private static final StringAttribute tokenAV 
    	= new StringAttribute("token");
    
    /**
     * The resource identifier for the introspect endpoint
     */
    private static final StringAttribute introspectAV 
    	= new StringAttribute("introspect");
    
    /**
     * The attribute indicating the token endpoint
     */
	private static final Attribute token 
		= new Attribute(RESOURCE_ID, null, null, tokenAV, false, 0);
	
	/**
	 * The attribute indicating the introspect endpoint
	 */
	private static final Attribute introspect 
		= new Attribute(RESOURCE_ID, null, null, introspectAV, false, 0);
	

	private static final Attributes tokenResource 
		= new Attributes(RESOURCE_CAT, Collections.singleton(token));
	
	private static final Attributes introspectResource
		= new Attributes(RESOURCE_CAT, Collections.singleton(introspect));
	

	/**
	 * 
	 * @param policyDirectory 
	 */
	public XacmlPDP(String policyDirectory) {
		Set<String> fileNames 
			= getFilesInFolder(policyDirectory, ".xml");
		PolicyFinder pf = new PolicyFinder();
		FileBasedPolicyFinderModule  pfm 
			= new FileBasedPolicyFinderModule(fileNames);
		pf.setModules(Collections.singleton(pfm));
		pfm.init(pf);
		this.pdp = new org.wso2.balana.PDP(new PDPConfig(null, pf, null));
	}
	
	@Override
	public boolean canAccessToken(String clientId) {
		Set<Attributes> attributes = new HashSet<>();
		attributes.add(tokenResource);
		StringAttribute subjectAV = new StringAttribute(clientId);
		Attribute subject = new Attribute(SUBJECT_ID, null, null, subjectAV, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
        while (results.hasNext()) {
        	AbstractResult result = results.next();
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		return false;
        	}
        }
        return true;
	}

	@Override
	public boolean canAccessIntrospect(String rsId) {
		Set<Attributes> attributes = new HashSet<>();
		attributes.add(introspectResource);
		StringAttribute subjectAV = new StringAttribute(rsId);
		Attribute subject = new Attribute(SUBJECT_ID, null, null, subjectAV, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
        while (results.hasNext()) {
        	AbstractResult result = results.next();
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		return false;
        	}
        }
        return true;
	}

	@Override
	public boolean canAccess(String clientId, String aud, String scope) {
		Set<Attributes> attributes = new HashSet<>();
		StringAttribute subjectAV = new StringAttribute(clientId);
		Attribute subject = new Attribute(SUBJECT_ID, null, null, subjectAV, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		StringAttribute audAV = new StringAttribute(aud);
		Attribute audA = new Attribute(URI.create("oauth2:audience"), null, null, audAV, 0);
		Attributes resourceCat = new Attributes(RESOURCE_CAT, Collections.singleton(audA));
		attributes.add(resourceCat);
		StringAttribute scopeAV = new StringAttribute(scope);
		Attribute scopeA = new Attribute(URI.create("oauth2:audience"), null, null, scopeAV, 0);
		Attributes actionCat = new Attributes(ACTION_CAT, Collections.singleton(scopeA));
		attributes.add(actionCat);
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
        while (results.hasNext()) {
        	AbstractResult result = results.next();
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		return false;
        	}
        }
        return true;
	}

	/**
	 * Get the files from a directory (optionally specifying the desired
	 * extension).
	 * 
	 * @param directory  the directory (full pathname)
	 * @param extension  the desired extension filter
	 * @return  the List of file names
	 */
	private Set<String> getFilesInFolder(String directory, 
			final String extension) {
		File dir = new File(directory);
		String[] children = null;
		if (extension != null) {
			FilenameFilter filter = new FilenameFilter() {
				@Override
				public boolean accept(File f, String name) {
					return name.endsWith(extension);
				}
			};
			children = dir.list(filter);
		} else {
			children = dir.list();
		}
		HashSet<String> result = new HashSet<>();
		for (int i=0; i<children.length;i++) {
			result.add(directory + System.getProperty("file.separator") + children[i]);
		}
		return result;
	}
}
