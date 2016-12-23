package se.sics.ace.rs;

import org.junit.Assert;
import org.junit.Test;

import se.sics.ace.AceException;
import se.sics.ace.examples.RESTscope;

/**
 * Tests for the RESTscope class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestRESTscope {
   
    /**
     * Test a scope against a resource URI that is not covered 
     * 
     * @throws AceException 
     */
    @Test
    public void testNoResource() throws AceException {
        String scope = "sensors/temp|1 config/security|5";
        RESTscope s = new RESTscope();
        Assert.assertFalse(s.scopeMatchResource(scope, "sensors/co2"));
        Assert.assertFalse(s.scopeMatch(scope, "blah", "GET"));
    }
    
    /**
     * Test a scope against different actions
     * 
     * @throws AceException 
     */
    @Test
    public void testNoPermission() throws AceException {
        // 1 = GET  5 = GET and PUT
        String scope = "sensors/temp|1 config/security|5";
        RESTscope s = new RESTscope();
        Assert.assertTrue(s.scopeMatchResource(scope, "sensors/temp"));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", "DELETE"));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", "PUT"));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", "POST"));
        Assert.assertTrue(s.scopeMatch(scope, "sensors/temp", "GET"));
        
        Assert.assertTrue(s.scopeMatchResource(scope, "config/security"));
        Assert.assertFalse(s.scopeMatch(scope, "config/security", "DELETE"));
        Assert.assertTrue(s.scopeMatch(scope, "config/security", "PUT"));
        Assert.assertFalse(s.scopeMatch(scope, "config/security", "POST"));
        Assert.assertTrue(s.scopeMatch(scope, "config/security", "GET"));
        
    }
    
    /**
     * Test a scope against with invalid action
     * 
     * @throws AceException 
     */
    @Test (expected = AceException.class)
    public void testInvalidAction() throws AceException {
        String scope = "sensors/temp:1 config/security:5";
        RESTscope s = new RESTscope();
        s.scopeMatch(scope, "sensors/temp", "PATCH");
        
    }
}
    
