package se.sics.ace.as;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test the KissPDP class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestKissPDP {
	  /**
     * Tests for CWT code.
     */
    public TestKissPDP() {
    }
    

    /**
     * 
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Test parsing an example configuration and running access queries
     * 
     * @throws Exception 
     */
    @Test
    public void testParseConfig() throws Exception {
    	KissPDP pdp = KissPDP.getInstance("src/test/resources/acl.json");
    	assert(pdp.canAccessToken("client_1"));
    	assert(pdp.canAccess("client_1", "rs_B", "r_light").equals("r_light"));
    	assert(pdp.canAccess("client_3", "rs_A", "r_temp")==null);
    	assert(pdp.canAccess("client_1", "rs_A", "r_temp").equals("r_temp"));
    	assert(pdp.canAccess("client_2", "rs_A", "r_config")==null);
    	assert(pdp.canAccessIntrospect("rs_A"));
    	assert(!pdp.canAccessToken("client_4"));
    	assert(!pdp.canAccessIntrospect("rs_D"));
    }
}
