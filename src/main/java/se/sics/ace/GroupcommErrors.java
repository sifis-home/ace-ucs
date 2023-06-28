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

/**
 * Values for the labels of the ACE Groupcomm Errors
 * 
 * @author Marco Tiloca
 *
 */

public class GroupcommErrors {

	public static final short ONLY_FOR_GROUP_MEMBERS = 0;
	
	public static final short INCONSISTENCY_WITH_ROLES = 1;
	
	public static final short INCOMPATIBLE_CRED = 2;
	
	public static final short INVALID_POP_EVIDENCE = 3;
	
	public static final short UNAVAILABLE_NODE_IDS = 4;
	
	public static final short MEMBERSHIP_TERMINATED = 5;
	
	public static final short GROUP_DELETED = 6;
	
	public static final short SIGNATURES_NOT_USED = 7;
	
	public static final short ONLY_FOR_SIGNATURE_VERIFIERS = 8;
	
	public static final short GROUP_NOT_ACTIVE = 9;
	
	public static final short GROUP_ACTIVE = 10;
	
	public static final short UNAVAILABLE_GROUP_NAMES = 11;
	
	public static final short UNSUPPORTED_GROUP_CONF = 12;

}
