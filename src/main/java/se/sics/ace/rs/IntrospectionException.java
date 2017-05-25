package se.sics.ace.rs;

/**
 * Exception thrown by the IntrospectionHandler to indicate errors at the AS.
 * 
 * Needed a separate class to distinguish these from AceExceptions.
 * 
 * @author Ludwig Seitz
 *
 */
public class IntrospectionException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -4345733975500623410L;

    /**
     * Error code received from the AS
     */
    private int code;
    
    /**
     * Constructor 
     * 
     * @param code  the error code received from the AS 
     * @param message  Exception message
     */
    public IntrospectionException(int code, String message) {
        super(message);
        this.code = code;
    }
    
    /**
     * @return  the error code
     */
    public int getCode() {
        return this.code;
    }
}
