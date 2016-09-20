package se.sics.ace.as;

/**
 * Exceptions related to the internal PDP of the AS.
 * 
 * @author Ludwig Seitz
 *
 */
public class PDPException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1398418923862910956L;

	/**
	 * Constructor.
	 * 
	 * @param msg  the error message
	 */
	public PDPException(String msg) {
		super(msg);
	}
}
