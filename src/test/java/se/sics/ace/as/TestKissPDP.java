/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
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
