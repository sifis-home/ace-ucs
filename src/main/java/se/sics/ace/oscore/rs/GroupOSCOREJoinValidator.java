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
package se.sics.ace.oscore.rs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.ScopeValidator;

/**
 * Audience and scope validator for testing purposes.
 * This validator expects the scopes to be either Strings as in OAuth 2.0,
 * or Byte Arrays to join OSCORE groups as per draft-ietf-ace-key-groupcomm-oscore
 * 
 * The actions are expected to be integers corresponding to the 
 * values for RESTful actions in <code>Constants</code>.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class GroupOSCOREJoinValidator implements AudienceValidator, ScopeValidator {

    /**
     * The audiences we recognize
     */
	private Set<String> myAudiences;
	
	// M.T.
	/**
     * The audiences acting as OSCORE Group Managers
     * Each of these audiences is also included in the main set "myAudiences"
     */
	private Set<String> myGMAudiences;
	
	// M.T.
	/**
     * The join resources exported by the OSCORE Group Manager to access an OSCORE group.
     * The name of the join resource is the zeroed-epoch Group ID of the OSCORE group.
     */
	private Set<String> myJoinResources;
	
	/**
	 * Maps the scopes to a map that maps the scope's resources to the actions 
	 * allowed on that resource
	 */
	private Map<String, Map<String, Set<Short>>> myScopes;  
	
	// M.T.
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 * @param myScopes  the scopes that this validator should accept
	 */
	public GroupOSCOREJoinValidator(Set<String> myAudiences, 
	        Map<String, Map<String, Set<Short>>> myScopes) {
		this.myAudiences = new HashSet<>();
		this.myGMAudiences = new HashSet<>(); // M.T:
		this.myJoinResources = new HashSet<>(); // M.T:
		this.myScopes = new HashMap<>();
		if (myAudiences != null) {
		    this.myAudiences.addAll(myAudiences);
		} else {
		    this.myAudiences = Collections.emptySet();
		}
		if (myScopes != null) {
		    this.myScopes.putAll(myScopes);
		} else {
		    this.myScopes = Collections.emptyMap();
		}
	}
	
	// M.T.
	/**
	 * Get the list of audiences acting as OSCORE Group Managers.
	 * 
	 * @return the audiences that this validator considers as OSCORE Group Managers
	 */
	public synchronized Set<String> getAllGMAudiences() {
		if (this.myGMAudiences != null)
			return this.myGMAudiences;
		else
			return Collections.emptySet();
	}
	
	// M.T.
	/**
	 * Set the list of audiences acting as OSCORE Group Managers.
	 * Check that each of those audiences are in the main set "myAudiences".
	 * 
	 * @param myGMAudiences  the audiences that this validator considers as OSCORE Group Managers
	 * 
	 * @throws AceException  if the group manager is not an accepted audience
	 */
	public synchronized void setGMAudiences(Set<String> myGMAudiences) throws AceException {
		if (myGMAudiences != null) {
			for (String foo : myGMAudiences) {
				if (!this.myAudiences.contains(foo)) {
					throw new AceException("This OSCORE Group Manager is not an accepted audience");
				}
                this.myGMAudiences.add(foo);
			}
		} else {
		    this.myGMAudiences = Collections.emptySet();
		}
	}
	
	// M.T.
	/**
	 * Remove an audience acting as OSCORE Group Manager from "myGMAudiences".
	 * This method does not remove the audience from the main set "myAudiences".
	 * 
	 * @param GMAudience  the audience acting as OSCORE Group Manager to be removed
	 * 
	 * @return true if the specified audience was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeGMAudience(String GMAudience){
		if (GMAudience != null)
			return this.myGMAudiences.remove(GMAudience);
		return false;
	}
	
	// M.T.
	/**
	 * Remove all the audiences acting as OSCORE Group Manager from "myGMAudiences".
	 * This method does not remove the audiences from the main set "myAudiences".
	 * 
	 */
	public synchronized void removeAllGMAudiences(){
		this.myGMAudiences.clear();
	}
	
	// M.T.
	/**
	 * Get the list of join resources to access an OSCORE group.
	 * The name of the join resource is the zeroed-epoch Group ID of the OSCORE group.
	 * 
	 * @return the resources that this validator considers as join resources to access an OSCORE group
	 */
	public synchronized Set<String> getAllJoinResources() {
		if (this.myJoinResources != null)
			return this.myJoinResources;
		else
		    return Collections.emptySet();
	}
	
	// M.T.
	/**
	 * Set the list of join resources to access an OSCORE group.
	 * The name of the join resource is the zeroed-epoch Group ID of the OSCORE group.
	 * 
	 * @param myJoinResources  the resources that this validator considers as join resources to access an OSCORE group
	 * .
	 * @throws AceException FIXME: when thrown?
	 */
	public synchronized void setJoinResources(Set<String> myJoinResources) throws AceException {
		if (myJoinResources != null) {
			for (String foo : myJoinResources)
				this.myJoinResources.add(foo);
		} else {
		    this.myJoinResources = Collections.emptySet();
		}
	}
	
	// M.T.
	/**
	 * Remove a join resource to access an OSCORE group from "myJoinResources".
	 * 
	 * @param joinResource  the join resource to remove.
	 * 
	 * @return true if the specified resource was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeJoinResource(String joinResource){
		if (joinResource != null)
			return this.myJoinResources.remove(joinResource);
		return false;
	}
	
	// M.T.
	/**
	 * Remove all the join resources to access an OSCORE group from "myJoinResources".
	 * 
	 */
	public synchronized void removeAllJoinResources(){
		this.myJoinResources.clear();
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

	// M.T.
    @Override
    public boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
            throws AceException {
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
        boolean isJoinResource = false;
    	boolean scopeMustBeBinary = false;
    	
    	System.out.println(resourceId);
    	if (this.myJoinResources.contains(resourceId))
    		isJoinResource = true;
    	
    	scopeMustBeBinary = isJoinResource;
        
    	if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		throw new AceException("Scope for this resource must be a byte string");
    	
        	String[] scopes = scope.AsString().split(" ");
            for (String subscope : scopes) {
                Map<String, Set<Short>> resources = this.myScopes.get(subscope);
                if (resources == null) {
                    continue;
                }
                if (resources.containsKey(resourceId)) {
                    if (resources.get(resourceId).contains(actionId)) {
                        return true;
                    }
                }
            }
            return false;
    	}
    	
    	else if (scope.getType().equals(CBORType.ByteString) && isJoinResource) {
        	
    		if ((short)actionId != Constants.POST)
    			throw new AceException("Invalid action on a join resource to access an OSCORE group");
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	if (cborScope.size() != 2)
        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
        	
        	// Retrieve the Group ID of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		scopeStr = scopeElement.AsString();
      	  	}
      	  	else {throw new AceException("The Group ID must be a CBOR Text String");}
        	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		scopeStr = scopeStr + "_" + scopeElement.AsString();
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			throw new AceException("The CBOR Array of roles must include at least two roles");
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString))
      	  				scopeStr = scopeStr + "_" + scopeElement.get(i).AsString();
      	  			else {throw new AceException("The roles must be CBOR Text Strings");}
      	  		}
      	  	}
      	  	else {throw new AceException("Invalid format of roles");}
      	  	
      	  	// scopeStr is either "<zeroed-epoch-Group-ID>_role1>" or "<zeroed-epoch-Group-ID>_role1_role2>"
      	  	Map<String, Set<Short>> resources = this.myScopes.get(scopeStr);
      	  	
      	  	if (resources == null)
      	  		return false;
      	  	
      	  	// resourceId is the zeroed-epoch Group ID of the OSCORE group
      	  	if (resources.containsKey(resourceId)) {
      	  		if (resources.get(resourceId).contains(actionId)) {
      	  			return true;
      	  		}
      	  	}
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a join resource to access an OSCORE group.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
        
        return false;
    	
    }

    // M.T.
    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {

        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
        boolean isJoinResource = false;
    	boolean scopeMustBeBinary = false;
    	if (this.myJoinResources.contains(resourceId))
    		isJoinResource = true;
    	
    	scopeMustBeBinary = isJoinResource;
        
    	if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		throw new AceException("Scope for this resource must be a byte string");
        
        	String[] scopes = scope.AsString().split(" ");
            for (String subscope : scopes) {           
                Map<String, Set<Short>> resources = this.myScopes.get(subscope);
                if (resources == null) {
                    continue;
                }
                if (resources.containsKey(resourceId)) {
                    return true;
                }
            }
            return false;
        	
    	}
    	
    	else if (scope.getType().equals(CBORType.ByteString) && isJoinResource) {
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	if (cborScope.size() != 2)
        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
        	
        	// Retrieve the Group ID of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		scopeStr = scopeElement.AsString();
      	  	}
      	  	else {throw new AceException("The Group ID must be a CBOR Text String");}
        	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		scopeStr = scopeStr + "_" + scopeElement.AsString();
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			throw new AceException("The CBOR Array of roles must include at least two roles");
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString))
      	  				scopeStr = scopeStr + "_" + scopeElement.get(i).AsString();
      	  			else {throw new AceException("The roles must be CBOR Text Strings");}
      	  		}
      	  	}
      	  	else {throw new AceException("Invalid format of roles");}
      	  	
      	  	// scopeStr is either "<zeroed-epoch-Group-ID>_role1>" or "<zeroed-epoch-Group-ID>_role1_role2>"
      	  	Map<String, Set<Short>> resources = this.myScopes.get(scopeStr);
      	  	
      	  	if (resources == null)
      	  		return false;
      	  	
      	  	// resourceId is the zeroed-epoch Group ID of the OSCORE group
      	  	if (resources.containsKey(resourceId))
      	  			return true;
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a join resource to access an OSCORE group.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
    	
    	return false;
    }

    @Override
    public boolean isScopeMeaningful(CBORObject scope) throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String if no audience is specified");
        }
        return this.myScopes.containsKey(scope.AsString());
    }
    
    @Override
    public boolean isScopeMeaningful(CBORObject scope, ArrayList<String> aud) throws AceException {
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
    	boolean scopeMustBeBinary = false;
    	boolean rsOSCOREGroupManager = false;
    	for (String foo : aud) {
    		if (this.myGMAudiences.contains(foo)) {
    			rsOSCOREGroupManager = true;
    			break;
    		}
    	}
    	scopeMustBeBinary = rsOSCOREGroupManager;
        
        if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		throw new AceException("Scope for this audience must be a byte string");
        	
        	return this.myScopes.containsKey(scope.AsString());
        	// The audiences are silently ignored
        }
        	
        else if (scope.getType().equals(CBORType.ByteString) && rsOSCOREGroupManager) {
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	if (cborScope.size() != 2)
        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
        	
        	// Retrieve the Group ID of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		scopeStr = scopeElement.AsString();
      	  	}
      	  	else {throw new AceException("The Group ID must be a CBOR Text String");}
        	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		scopeStr = scopeStr + "_" + scopeElement.AsString();
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			throw new AceException("The CBOR Array of roles must include at least two roles");
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString))
      	  				scopeStr = scopeStr + "_" + scopeElement.get(i).AsString();
      	  			else {throw new AceException("The roles must be CBOR Text Strings");}
      	  		}
      	  	}
      	  	else {throw new AceException("Invalid format of roles");}
      	  	
        	return this.myScopes.containsKey(scopeStr);
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the audience is not related to an OSCORE Group Manager.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
        
        return false;
        
    }

    @Override
    public CBORObject getScope(String resource, short action) {
        // TODO Auto-generated method stub
        return null;
    }
}
