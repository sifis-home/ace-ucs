package se.sics.ace.rs;

/**
 * Interface for validating audience claims.  Concrete implementations are application specific.
 * 
 * @author Ludwig Seitz
 *
 */
public interface AudienceValidator {
	
	/**
	 * @param aud  the audience
	 * @return  Does the given audience include us?
	 */
	public boolean match(String aud);

}
