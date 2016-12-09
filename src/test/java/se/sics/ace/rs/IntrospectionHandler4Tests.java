package se.sics.ace.rs;

import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.as.Introspect;
import se.sics.ace.as.Message4Tests;

/**
 * An introspection handler that directly uses a se.sics.as.Introspect instance
 * for testing purposes.
 * 
 * @author Ludwig Seitz
 *
 */
public class IntrospectionHandler4Tests implements IntrospectionHandler {

    private Introspect i;
    
    private String rsId;
    
    private String asId; 
    
    /**
     * Create a new test instrospection handler
     * 
     * @param i  the introspect library
     * @param rsId  the resource server's identifier
     * @param asId  the AS identifier
     */
    public IntrospectionHandler4Tests(Introspect i, String rsId, String asId) {
        this.i = i;
        this.rsId = rsId;
        this.asId = asId;
    }
  
    
    @Override
    public Map<String, CBORObject> getParams(String tokenReference) {
        Map<String, CBORObject> params = new HashMap<>();
        params.put("token", 
                CBORObject.FromObject(tokenReference));
        params.put("token_type_hint", 
                CBORObject.FromObject("pop"));
        Message4Tests req = new Message4Tests(0, this.rsId, this.asId, params);
        Message4Tests res = (Message4Tests)this.i.processMessage(req);
        return res.getParameters();
    }

}
