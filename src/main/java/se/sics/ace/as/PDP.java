/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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

import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import se.sics.ace.AceException;
import se.sics.ace.coap.as.CoapDtlsEndpoint;

/**
 * An interface for the Policy Decision Point that this AS uses to make 
 * authorization decisions.
 * 
 * @author Ludwig Seitz and Marco Rasori
 *
 */
public interface PDP {

	/**
	 * The different access rights for introspection.
	 * NONE has no right to introspect,
	 * ACTIVE_ONLY only gets to see if the token is active
	 * ACTIVE_AND_CLAIMS gets to see the claims in the token as well
	 *
	 */
	enum IntrospectAccessLevel {
		NONE,
		ACTIVE_ONLY,
		ACTIVE_AND_CLAIMS;
	}

	/**
	 * Checks if this client can access the /token endpoint.
	 * 
	 * @param clientId  the identifier of the client.
	 * 
	 * @return  true if the client can access, false otherwise
	 * @throws AceException 
	 */
	public abstract boolean canAccessToken(String clientId) 
	        throws AceException;
	
	/**
	 * Checks if this RS can access the /introspect endpoint, returning the access level.
	 * 
	 * @param rsId  the identifier of the RS.
	 * @return  A value of IntrospectAccessLevel indicating the introspection access level.
	 * @throws AceException 
	 */
	public abstract IntrospectAccessLevel getIntrospectAccessLevel(String rsId)
	        throws AceException;
	
	/**
	 * Checks if the given client can get an access token for the given 
	 * audience and scope.
	 * 
	 * @param clientId  the identifier of the client
	 * @param aud  the audiences for which the client request access 
	 * @param scopes  the scope(s) requested for the access token, if present, 
	 * 	           or null. Note that the scopes must be separated by spaces if
	 * 			   there are several
	 * 
	 * @return  The scopes that can be granted or null if access id denied
	 * 
	 *  @throws AceException  
	 */
	public abstract Object canAccess(String clientId, Set<String> aud,
										Object scopes, int evaluationId) throws AceException;


	void close() throws Exception;

	void addIntrospectAccess(String name) throws AceException;

	void addTokenAccess(String name) throws AceException;

	void addAccess(String name, String aud, String s) throws AceException;


	public void updateSessionsWithCti(String cti, int evaluationId) throws AceException;

	public void terminatePendingSessions(int evaluationId) throws AceException;

	void setRevocationHandler(RevocationHandler rh);

	void revokeToken(String cti) throws AceException;

	/**
	 * Removes the sessions associated with the provided token identifier
	 *
	 * @param cti
	 */
	void removeSessions4Cti(String cti) throws AceException;

	void setTokenEndpoint(Token t);
}
