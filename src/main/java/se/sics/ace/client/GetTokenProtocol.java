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
package se.sics.ace.client;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Constants;
import se.sics.ace.Protocol;

/**
 * Client protocol for getting a token from the /token endpoint at the AS.
 * Note that this implementation only supports the client_credentials 
 * grant type.
 * 
 * @author Ludwig Seitz
 *
 */
public class GetTokenProtocol implements Protocol {

	/**
	 * First step of the get token protocol
	 */
	public static int preparingGet = 0;
	
	/**
	 * Second step of the get token protocol
	 */
	public static int getSent = 1;
	
	/**
	 * Third step of the get token protocol 
	 */
	public static int responseReceived = 2;
	
	@Override
    public int getState() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
    public int getParty() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	
	/**
	 * Create a get message.
	 * 
	 * @param audience  the desired audience or null if a default audience is 
	 *     specified at the AS
	 * @param clientId  the client identifier
	 * @param scope  the desired scope or null if a default scope is specified at
	 *     the AS
	 * @param clientSecret  the client secret or null if not needed with this
	 *     grant type
	 *     
	 * @return  the get-message payload
	 */
	public CBORObject makeGetMessage(String audience, String clientId,
			String scope, String clientSecret) {
		CBORObject params = CBORObject.NewMap();
		params.Add(Constants.GRANT_TYPE, Constants.GT_CLI_CRED);
		params.Add(Constants.AUD, audience);
		params.Add(Constants.CLIENT_ID, clientId);
		params.Add(Constants.SCOPE, scope);
		params.Add(Constants.CLIENT_SECRET, clientSecret);
		
		//FIXME: return something meaningful
		return params;
	}
	
	
}
