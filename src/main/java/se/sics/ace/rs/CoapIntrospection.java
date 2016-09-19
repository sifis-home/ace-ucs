package se.sics.ace.rs;

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

/**
 * An IntrospectionHandler that uses CoAP to talk to the /introspect endpoint at the AS.
 * 
 * @author Ludwig Seitz
 */
public class CoapIntrospection implements IntrospectionHandler {

	private String asAddress;
	
	/**
	 * Constructor.
	 * 
	 * @param asAddress  the base address of the AS
	 */
	public CoapIntrospection(String asAddress) {
		this.asAddress = asAddress;
	}
	
	
	@Override
	public Map<String, CBORObject> getParams(String tokenReference) throws RSException {
		CBORObject requestParams = CBORObject.NewMap();
		requestParams.Add(CBORObject.FromObject("token"), 
				CBORObject.FromObject(tokenReference));
		requestParams.Add(CBORObject.FromObject("token_type_hint"), 
				CBORObject.FromObject("pop"));
		
		//FIXME: Generate CoAP request
		
		//FIXME: Retrieve CoAP response
		
		//FIXME
		return null;
	}

}
