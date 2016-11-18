package se.sics.ace;


import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;

import com.upokecenter.cbor.CBORObject;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoAPResponse extends Response implements Message {
    
    /**
     * The parameters in the payload of this message as a Map for convenience.
     * This is null if the payload is empty or not a CBOR Map.
     */
    private Map<String, CBORObject> parameters = null;
    
    
    /**
     * Constructor
     * 
     * @param code  the response code
     * @param payload  the response payload, may be null
     * @param request   the request this responds to
     */
    public CoAPResponse(ResponseCode code, CBORObject payload) {
        super(code);
        super.setPayload(payload.EncodeToBytes());   
    }

    /**
     * Constructor
     * 
     * @param code  the response code
     * @param parameters  the response parameters
     * @param request   the request this responds to
     */
    public CoAPResponse(ResponseCode code, Map<String, CBORObject> parameters) {
        super(code);
        this.parameters.putAll(parameters);
        CBORObject map = CBORObject.NewMap();
        for (String key : this.parameters.keySet()) {
            short i = Constants.getAbbrev(key);
            if (i != -1) {
                map.Add(CBORObject.FromObject(i), this.parameters.get(key));
            } else { //This claim/parameter has no abbreviation
                map.Add(CBORObject.FromObject(key), this.parameters.get(key));
            }
        }
        super.setPayload(map.EncodeToBytes());   
    }
    
    @Override
    public byte[] getRawPayload() {
        return super.getPayload();
    }

    @Override
    public String getSenderId() {
        return null;
    }

    @Override
    public Set<String> getParameterNames() {
        if (this.parameters != null) {
            return this.parameters.keySet();
        }
        return null;
    }

    @Override
    public CBORObject getParameter(String name) {
        if (this.parameters != null) {
            return this.parameters.get(name);
        }
        return null;
    }

    @Override
    public Map<String, CBORObject> getParameters() {
        if (this.parameters != null) {
            Map<String, CBORObject> map = new HashMap<>();
            map.putAll(this.parameters);
            return map;
        }
        return null;
    }

    @Override
    public Message successReply(int code, CBORObject payload) {
        return null; //No generating a response to a response
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        return null; //No generating a response to a response
    }

}
