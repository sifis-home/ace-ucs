package se.sics.ace.ucs.properties;

import it.cnr.iit.ucs.properties.components.PapProperties;

import java.io.File;
import java.util.Map;

public class UcsPapProperties implements PapProperties {

	private String path;

	public UcsPapProperties(String path) {
		this.path = path;
	}

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.pap.PolicyAdministrationPoint";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
		return null;
	}

	@Override
	public String getId() {
		return "1";
	}

	/**
	 * Get the path where policy files are stored
	 *
	 * @return the path where policy files are stored
	 */
	@Override
	public String getPath() {
		return this.path;
	}

	/**
	 * Set the path where policy files are stored
	 *
	 * @param path the path where policy files are stored
	 */
	public void setPath(String path) {
		this.path = path;
	}
}
