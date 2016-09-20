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

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * @author Ludwig Seitz
 *
 */
public class Token implements Endpoint {

	@Override
	public Message processMessage(Message msg, CwtCryptoCtx ctx) {
		CBORObject payload = CBORObject.FromObject(msg.getRawPayload());
		
		//1. Check if this client can request tokens
		msg.getSenderId();
		
		//2. Check if this client can request this type of token
		//2.1 check aud & scope
		//3. Check if this client and the RS support a common profile
		//4. Create token
		
		
		return null; //FIXME
	}

}
