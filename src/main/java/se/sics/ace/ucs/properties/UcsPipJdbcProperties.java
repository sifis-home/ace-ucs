package se.sics.ace.ucs.properties;

import it.cnr.iit.ucs.properties.components.PipProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UcsPipJdbcProperties implements PipProperties {

	List<Map<String, String>> attributes = new ArrayList<>();

	@Override
	public String getName() {
		return "it.cnr.iit.ucs.pipjdbc.PIPJdbc";
	}

	@Override
	public Map<String, String> getAdditionalProperties() {
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
		return new ArrayList<>(attributes);
	}

	public void addAttribute(String id, String category, String dataType, String filePath, String dbUri) {
		Map<String,String> attributeMap = new HashMap<>();
		attributeMap.put("ATTRIBUTE_ID", id);
		attributeMap.put("CATEGORY", category);
		attributeMap.put("EXPECTED_CATEGORY", category);
		attributeMap.put("DATA_TYPE", dataType);
		attributeMap.put("FILE_PATH", filePath);
		//attributeMap.put("DB_URI", "jdbc:sqlite:memory:myDb");
		attributeMap.put("DB_URI", dbUri);

		this.attributes.add(attributeMap);
	}

	public void addAttribute(String id, String category, String dataType,
							 String filePath, String dbUri, String expectedCategory) {
		Map<String,String> attributeMap = new HashMap<>();
		attributeMap.put("ATTRIBUTE_ID", id);
		attributeMap.put("CATEGORY", category);
		attributeMap.put("EXPECTED_CATEGORY", expectedCategory);
		attributeMap.put("DATA_TYPE", dataType);
		attributeMap.put("FILE_PATH", filePath);
		//attributeMap.put("DB_URI", "jdbc:sqlite:memory:myDb");
		attributeMap.put("DB_URI", dbUri);

		this.attributes.add(attributeMap);
	}

	@Override
	public boolean isMultiAttribute() {
		return this.attributes.size() > 1;
	}

}
