package se.sics.ace.rs;

import java.util.HashSet;
import java.util.Set;

/**
 * Simple audience validator for testing purposes.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissAudValidator implements AudienceValidator {

	private Set<String> myAudiences;
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 */
	public KissAudValidator(Set<String> myAudiences) {
		this.myAudiences = new HashSet<>();
		this.myAudiences.addAll(myAudiences);
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

}
