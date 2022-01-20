package se.sics.ace.ucs.xacml;

public class AdditionalAttribute {
	private CATEGORY category;
	private String name;
	private String value;
	private String dataType;

	public AdditionalAttribute() {
	}

	public AdditionalAttribute(CATEGORY category, String name, String value, String dataType) {
		this.category = category;
		this.name = name;
		this.value = value;
		this.dataType = dataType;
	}

	public CATEGORY getCategory() {
		return category;
	}

	public void setCategory(CATEGORY category) {
		this.category = category;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getDataType() {
		return dataType;
	}

	public void setDataType(String dataType) {
		this.dataType = dataType;
	}
}
