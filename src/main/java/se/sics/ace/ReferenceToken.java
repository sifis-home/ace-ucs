package se.sics.ace;

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.RSException;

/**
 * This class implements a reference token.
 * 
 * @author Ludwig Seitz
 *
 */
public class ReferenceToken implements AccessToken {

	/**
	 * The reference 
	 */
	private String ref;
	
	/**
	 * A handler for introspecting this token.
	 */
	private IntrospectionHandler introspect;
	
	@Override
	public boolean expired(long now) throws TokenException {
		if (this.introspect == null) {
			throw new TokenException("Need IntrospectionHandler");
		}
		Map<String, CBORObject> params = this.introspect.getParams(ref);
		CBORObject expO = params.get("exp");
		if (expO != null && expO.AsInt64() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}

	@Override
	public boolean isValid(long now) throws TokenException {
		if (this.introspect == null) {
			throw new TokenException("Need IntrospectionHandler");
		}
		Map<String, CBORObject> params = this.introspect.getParams(ref);
		//Check nbf and exp for the found match
				CBORObject nbfO = params.get("nbf");
				if (nbfO != null &&  nbfO.AsInt64()	> now) {
					return false;
				}	
				CBORObject expO = params.get("exp");
				if (expO != null && expO.AsInt64() < now) {
					//Token has expired
					return false;
				}
		return false;
	}

	@Override
	public CBORObject encode() {
		return CBORObject.FromObject(this.ref);
	}

}
