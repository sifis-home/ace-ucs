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
package se.sics.ace;

import java.util.HashSet;
import java.util.Set;

/**
 * Constants for use with ACE Groupcomm.
 * 
 * @author Marco Tiloca
 *
 */

public class GroupcommParameters {
	
    /**
	 * Group OSCORE abbreviations =================================
	 */

    /**
     * The OSCORE group uses only the group mode
     */
    public static final short GROUP_OSCORE_GROUP_MODE_ONLY = 1;
    
    /**
     * The OSCORE group uses both the group mode and the pairwise mode
     */
    public static final short GROUP_OSCORE_GROUP_PAIRWISE_MODE = 2;
    
    /**
     * The OSCORE group uses only the pairwise mode
     */
    public static final short GROUP_OSCORE_PAIRWISE_MODE_ONLY = 3;
    
    
    /**
     * Requester role
     */
    public static final short GROUP_OSCORE_REQUESTER = 1;
    
    /**
     * Responder role
     */
    public static final short GROUP_OSCORE_RESPONDER = 2;
    
    /**
     * Monitor role
     */
    public static final short GROUP_OSCORE_MONITOR = 3;
    
    /**
     * Verifier role
     */
    public static final short GROUP_OSCORE_VERIFIER = 4;
    
    /**
     * Roles as strings
     */
    public static final String[] GROUP_OSCORE_ROLES = {"reserved", "requester", "responder", "monitor", "verifier"};
    
    /**
     * Return a set of integers including the valid Group OSCORE role combinations
	 *
     * @return  the set of valid Group OSCORE combinations
     */
    public static Set<Integer> getValidGroupOSCORERoleCombinations() {

    	Set<Integer> validRoleCombinations = new HashSet<Integer>();
    	
        // Set the valid combinations of roles in a Joining Request
        // Combinations are expressed with the AIF specific data model AIF-OSCORE-GROUPCOMM
        validRoleCombinations.add(1 << GROUP_OSCORE_REQUESTER);   // Requester (2)
        validRoleCombinations.add(1 << GROUP_OSCORE_RESPONDER);   // Responder (4)
        validRoleCombinations.add((1 << GROUP_OSCORE_REQUESTER) +
        		                  (1 << GROUP_OSCORE_RESPONDER)); // Requester+Responder (6)
        validRoleCombinations.add(1 << GROUP_OSCORE_MONITOR);     // Monitor (8)
    	
    	return validRoleCombinations;
    }
	
}
