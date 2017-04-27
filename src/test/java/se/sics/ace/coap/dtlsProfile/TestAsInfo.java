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
package se.sics.ace.coap.dtlsProfile;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.coap.rs.dtlsProfile.AsInfo;

/**
 * Tests the DTLSProfileAsInfo class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestAsInfo {
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Test creating an AS info with null as AS uri.
     */
    @Test
    public void testNullUri() {
        this.thrown.expect(IllegalArgumentException.class);
        this.thrown.expectMessage("Cannot create an DTLSProfileAsInfo object "
                    + "with null or empty asUri field");
        @SuppressWarnings("unused")
        AsInfo ai = new AsInfo(null);
    }
    
    /**
     * Test creating an AS info with empty AS uri.
     */
    @Test
    public void testEmptyUri() {
        this.thrown.expect(IllegalArgumentException.class);
        this.thrown.expectMessage("Cannot create an DTLSProfileAsInfo object "
                    + "with null or empty asUri field");
        @SuppressWarnings("unused")
        AsInfo ai = new AsInfo("");
    }
    
    /**
     * Test round trips with creating and parsing AS information
     * 
     * @throws AceException
     */
    @Test 
    public void testRoundTrip() throws AceException {
        AsInfo ai = new AsInfo("coaps://blah/authz-info/");
        CBORObject cbor = ai.getCBOR();
        AsInfo ai2 = AsInfo.parse(cbor.EncodeToBytes());
        Assert.assertEquals(ai.getAsUri(), ai2.getAsUri());
        Assert.assertNull(ai.getNonce());
        
        byte[] nonce = {0x00, 0x01, 0x02};
        ai = new AsInfo("blah", nonce);
        cbor = ai.getCBOR();
        ai2 = AsInfo.parse(cbor.EncodeToBytes());
        Assert.assertEquals(ai.getAsUri(), ai2.getAsUri());
        Assert.assertArrayEquals(nonce, ai2.getNonce());
    }

}
