package se.sics.ace.ucs.xacml;

public enum CATEGORY {
	ACTION("urn:oasis:names:tc:xacml:3.0:attribute-category:action"),
	RESOURCE("urn:oasis:names:tc:xacml:3.0:attribute-category:resource"),
	SUBJECT("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"),
	ENVIRONMENT("urn:oasis:names:tc:xacml:3.0:attribute-category:environment"),
	ORGANIZATION("urn:oasis:names:tc:xacml:3.0:attribute-category:organisation");

	private final String data;

	CATEGORY(String data) {
		this.data = data;
	}

	@Override
	public String toString() {
		return data;
	}

	public static CATEGORY toCATEGORY(String category) {
		if (category.equalsIgnoreCase(ACTION.toString())) {
			return ACTION;
		}
		if (category.equalsIgnoreCase(RESOURCE.toString())) {
			return RESOURCE;
		}
		if (category.equalsIgnoreCase(SUBJECT.toString())) {
			return SUBJECT;
		}
		if (category.equalsIgnoreCase(ENVIRONMENT.toString())) {
			return ENVIRONMENT;
		}
		return null;
	}

	public boolean contains(String string) {
		return data.contains(string);
	}
}
