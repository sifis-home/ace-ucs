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

	public static int preparingGet = 0;
	public static int getSent = 1;
	public static int responseReceived = 2;
	
	public int getState() {
		// TODO Auto-generated method stub
		return 0;
	}

	public int getParty() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	
	public CBORObject makeGetMessage(String audience, String clientId,
			String scope, String clientSecret) {
		CBORObject params = CBORObject.NewMap();
		params.Add(Constants.GRANT_TYPE, Constants.GT_CLI_CRED);
		params.Add(Constants.AUD, audience);
		params.Add(Constants.CLIENT_ID, clientId);
		params.Add(Constants.SCOPE, scope);
		params.Add(Constants.CLIENT_SECRET, clientSecret);
		
		//FIXME:
		return params;
	}
	
	
}
