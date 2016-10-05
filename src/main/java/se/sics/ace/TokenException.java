package se.sics.ace;

/**
 * Exceptions related to the /token endpoint of the AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class TokenException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 3140706692045141425L;

	/**
	 * Constructor.
	 * 
	 * @param msg  the error message
	 */
	public TokenException(String msg) {
		super(msg);
	}
}
