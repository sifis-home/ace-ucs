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
package se.sics.ace.oscore.rs.oscoreGroupManager;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;

/**
 * Definition of the Group OSCORE group-membership sub-resource /policies
 */
public class GroupOSCORESubResourcePolicies extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORESubResourcePolicies(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"policies\" " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
        
    }

    @Override
    public void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
  		if (!groupName.equals(this.getParent().getName())) {
    	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
    					 "Error when retrieving material for the OSCORE group");
			return;
		}
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
    	
    	if (!targetedGroup.isGroupMember(subject)) {	
    		// The requester is not a current group member.
    		CBORObject responseMap = CBORObject.NewMap();
    		responseMap.Add(GroupcommParameters.ERROR, GroupcommErrors.ONLY_FOR_GROUP_MEMBERS);
    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 responsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
        	
    	// Respond to the Policies Request
        
    	CBORObject myResponse = null;
    	CBORObject groupPolicies = targetedGroup.getGroupPolicies();
    	
    	if (groupPolicies == null) {
        	// This should not happen for this Group Manager, since default policies apply
    		// if not specified when creating the group
    		myResponse = CBORObject.FromObject(new byte[0]);
    	}
    	else {
    		myResponse = CBORObject.NewMap();
    		myResponse.Add(GroupcommParameters.GROUP_POLICIES, groupPolicies);
    	}
    	
    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
}
