package se.sics.ace.as;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Message;

/**
 * A testing class implementing a dummy message. 
 * 
 * @author Ludwig Seitz
 *
 */
public class TestMessage implements Message {

    /**
     * The authenticated id of the sender
     */
    private String senderId;
    
    /**
     * The parameters contained in the payload of this message
     */
    private Map<String, CBORObject> params;
    
    /**
     * Constructor.
     * @param senderId
     * @param parameters
     * @param rawPayload
     */
    public TestMessage(String senderId, Map<String, CBORObject> parameters) {
        this.senderId = senderId;
        this.params = new HashMap<>();
        this.params.putAll(parameters);
        
    }

    
    @Override
    public Message successReply(int code, CBORObject payload) {
        //FIXME:
        return new TestMessage("", null);
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        //FIXME: 
        return new TestMessage("", null);
    }


    @Override
    public byte[] getRawPayload() {
        // Not needed
        return null;
    }


    @Override
    public String getSenderId() {
        return this.senderId;
    }


    @Override
    public Set<String> getParameterNames() {
        return this.params.keySet();
    }


    @Override
    public CBORObject getParameter(String name) {
        return this.params.get(name);
    }


    @Override
    public Map<String, CBORObject> getParameters() {
        HashMap<String, CBORObject> ret = new HashMap<>();
       ret.putAll(this.params);
       return ret;
    }

}
