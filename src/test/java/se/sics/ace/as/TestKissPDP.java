/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
