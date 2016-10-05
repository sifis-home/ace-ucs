package se.sics.ace;

import com.upokecenter.cbor.CBORObject;

/**
 * An interface with methods that access tokens need to implement.
 *  
 * @author Ludwig Seitz
 *
 */
public interface AccessToken {

	/**
	 * Checks if the token is expired at the given time
	 * 
	 * @param now  the time for which the expiry should be checked
	 * 
	 * @return  true if the token is expired, false if it is still valid
	 * @throws TokenException 
	 */
	public boolean expired(long now) throws TokenException;
	
	/**
	 * Checks if the token is still valid (including expiration).
	 * Note that this method may need to perform introspection.
	 * 
	 * @param now  the time for which validity should be checked
	 * 
	 * @return  true if the token is valid, false if it is invalid
	 */
	public boolean isValid(long now) throws TokenException;
	
	
	/**
	 * Encodes this Access Token as a CBOR Object.
	 * 
	 * @return  the encoding of the token.
	 */
	public CBORObject encode();
	
}
