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

/**
 * An interface for the Policy Decision Point that this AS uses to make 
 * authorization decisions.
 * 
 * @author Ludwig Seitz
 *
 */
public interface PDP {

	/**
	 * Checks if this client can access the /token endpoint.
	 * 
	 * @param clientId  the identifier of the client.
	 * 
	 * @return  true if the client can access, false otherwise
	 */
	public abstract boolean canAccessToken(String clientId);
	
	/**
	 * Checks if this RS can access the /introspect endpoint.
	 * 
	 * @param rsId  the identifier of the RS.
	 * @return  true if the RS can access, false otherwise
	 */
	public abstract boolean canAccessIntrospect(String rsId);
	
	/**
	 * Checks if the given client can get an access token for the given 
	 * audience and scope.
	 * 
	 * @param clientId  the identifier of the client
	 * @param aud  the audience requested for the access token, if present, 
	 * 			   or null
	 * @param scope  the scope requested for the access token, if present, 
	 * 	           or null
	 * 
	 * @return  true if the access token should be granted, false if not
	 */
	public abstract boolean canAccess(String clientId, String aud, 
				String scope);
}
