package se.sics.ace.ucs.properties;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.cnr.iit.ucs.properties.components.PipProperties;

public class UcsPipProperties implements PipProperties {

	private long refreshRate;

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.pipreader.PIPReader";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
//		Map<String, String> additionalProperties = new HashMap<>();
//		additionalProperties.put("KEY", "VALUE");
//		return additionalProperties;
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

	@Override
	public List<Map<String, String>> getAttributes() {

		Map<String,String> attributeMap = new HashMap<>();
		attributeMap.put("ATTRIBUTE_ID","urn:oasis:names:tc:xacml:3.0:environment:dummy_env_attribute");
		attributeMap.put("CATEGORY", "urn:oasis:names:tc:xacml:3.0:attribute-category:environment");
		attributeMap.put("DATA_TYPE","http://www.w3.org/2001/XMLSchema#string");

		File file = new File("src/test/resources/attributes/");
		String filePath = file.getAbsolutePath() + "/dummy_env_attribute.txt";

		attributeMap.put("FILE_PATH",filePath);

		List<Map<String, String>> attributes = new ArrayList<>();
		attributes.add(0,attributeMap);

		return attributes;
	}

	@Override
	public boolean isMultiAttribute() {
		return false;
	}

	@Override
	public long getRefreshRate() {
		return refreshRate;
	}

	public void setRefreshRate(long refreshRate) {
		this.refreshRate = refreshRate;
	}
}
