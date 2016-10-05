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

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AccessToken;
import se.sics.ace.ReferenceToken;
import se.sics.ace.cwt.CWT;

/**
 * Factory that creates different types of access tokens.
 * 
 * @author Ludwig Seitz
 *
 */
public class AccessTokenFactory {
	
	/**
	 * The type identifier for CWTs
	 */
	public static final int CWT_TYPE = 0;
	
	/**
	 * The type identifier for reference tokens
	 */
	public static final int REF_TYPE = 1;
	
	/**
	 * Default length of the reference tokens
	 */
	private static int defaultRefLength = 128;
	
	/**
	 * Generate an access token.
	 * 
	 * @param type  the type of token you want to generate
	 * @param claims  the claims associated with this token
	 * @return  the generated token
	 * @throws ASException
	 */
	public static AccessToken generateToken(
			int type, Map<String, CBORObject> claims) throws ASException {
		switch (type) {
		case CWT_TYPE :
			return new CWT(claims);
		case REF_TYPE :
			return new ReferenceToken(AccessTokenFactory.defaultRefLength);	
		default: 
			throw new ASException("Unsupported token type");
		}
	}

	/**
	 * Set the length of reference tokens create by this factory.
	 * 
	 * @param length  the length to set
	 */
	public static void setDefaultRefLength(int length) {
		AccessTokenFactory.defaultRefLength = length;
	}

}
