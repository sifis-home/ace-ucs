package se.sics.ace.ucs.properties;

import it.cnr.iit.ucs.properties.components.PapProperties;

import java.io.File;
import java.util.Map;

public class UcsPapProperties implements PapProperties {

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

	@Override
	public String getPath() {
//		ClassLoader classLoader = getClass().getClassLoader();
//		File file = new File(classLoader.getResource("policy").getFile());
//		return file.getAbsolutePath();
//		return "/home/simfac/work/ACE-java/ace-java/src/main/resources/";

		// TODO:  fix the path for Windows systems, or handle it better
		File file = new File("src/test/resources/policies/");
		return file.getAbsolutePath() + "/";
	}

}
