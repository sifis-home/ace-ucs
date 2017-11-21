/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
package se.sics.ace.rs;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.examples.RESTscope;

/**
 * Tests for the RESTscope class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestRESTscope {
   
    private static CBORObject scope;
    private static RESTscope s = new RESTscope();
    
    /**
     * Set up tests.
     */
    @BeforeClass
    public static void setUp()  {
        scope = CBORObject.NewArray();
        CBORObject authz1 = CBORObject.NewArray();
        CBORObject authz2 = CBORObject.NewArray();
        authz1.Add("sensors/temp");
        authz1.Add(1);
        authz2.Add("config/security");
        authz2.Add(5);
        scope.Add(authz1);
        scope.Add(authz2);
    }
    
    
    /**
     * Test a scope against a resource URI that is not covered 
     * 
     * @throws AceException 
     */
    @Test
    public void testNoResource() throws AceException {
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
         s.scopeMatch(scope, "sensors/temp", "BLAH");
        
    }
}
    
