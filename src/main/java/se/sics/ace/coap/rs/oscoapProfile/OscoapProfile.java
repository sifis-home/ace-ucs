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
package se.sics.ace.coap.rs.oscoapProfile;

import org.eclipse.californium.core.OSCoapServer;
import org.eclipse.californium.core.network.stack.oscoap.OscoapCtxDB;

import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.rs.AsInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;

/**
 * Implements the OSCOAP profile of ACE
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoapProfile extends OSCoapServer {

    /**
     * Constructor.
     *
     * @param ctxDB  the OSCOAP context database 
     * @param tr  the token repository 
     * @param i   the introspection handler or null for no introspection
     * @param asInfo  the information about the AS responsible for this RS
     */
    public OscoapProfile(OscoapCtxDB ctxDB, TokenRepository tr, 
            IntrospectionHandler i, AsInfo asInfo) {
        super(ctxDB);
        this.setMessageDeliverer(new CoapDeliverer(this.getRoot(), 
                tr, i, asInfo));
    }
    
    

}
