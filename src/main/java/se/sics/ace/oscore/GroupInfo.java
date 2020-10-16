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
package se.sics.ace.oscore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.Constants;

/**
 * A class implementing the status of an OSCORE Group at its Group ManagerOSCORE
 *  
 * @author Marco Tiloca
 *
 */
public class GroupInfo {

	/**
	 * Information element for the OSCORE group
	 */
	
	private String groupName;
	
	private byte[] masterSecret;
	private byte[] masterSalt;
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 includes as elements Sender IDs with size 1 byte.
	private List<Set<Integer>> usedSenderIds = new ArrayList<Set<Integer>>();
	
	private int senderIdSize; // Size in bytes of the byte array representation of Sender IDs 
	private int maxSenderIdValue;
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 has elements referring to Sender IDs with size 1 byte.
	// Each map has as value the public keys of the group members as COSE Keys (CBOR Maps).
	// The map key (label) is the integer representation of the Sender ID of the group member.
	private List<Map<Integer, CBORObject>> publicKeyRepo = new ArrayList<Map<Integer, CBORObject>>();
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 has elements referring to Sender IDs with size 1 byte.
	// Each map has as value the AIF-based role(s) of group members.
	// The map key (label) is the integer representation of the Sender ID of the group member.
	private List<Map<Integer, Integer>> nodeRoles = new ArrayList<Map<Integer, Integer>>();
	
	// The value of each map entry is the node name of a group member with a certain identity.
	// The map (key) label is the identity of each group member, as per its secure association with the Group Manager.
	private Map<String, String> identities2nodeNames = new HashMap<String, String>();
	
	private final int groupIdPrefixSize; // Prefix size (bytes), same for every Group ID on the same Group Manager
	private byte[] groupIdPrefix;
	
	private final String prefixMonitorNames; // Initial part of the node name for monitors, since they do not have a Sender ID
	
	// Each element of the set is an allocated variable part of the node name for monitors, since they do not have a Sender ID
	private Set<Integer> suffixMonitorNames = new HashSet<Integer>();
	
	private int groupIdEpochSize; // Epoch size (bytes) in the {Prefix ; Epoch} Group ID
	private int maxGroupIdEpochValue;
	private int groupIdEpoch;
	
	private AlgorithmID alg = null;
	private AlgorithmID hkdf = null;
	private AlgorithmID csAlg = null;
	private CBORObject csParams = null;
	private CBORObject csKeyParams = null;
	private CBORObject csKeyEnc = null;
	private CBORObject groupPolicies = null;
	
	private int version; // Version of the current symmetric keying material
	private boolean status; // True if the group is currently active, false otherwise
	
	/**
	 * Creates a new GroupInfo object tracking the current status of an OSCORE group.
	 * 
	 * @param groupName           the invariant name of the OSCORE group.
	 * @param masterSecret        the OSCORE Master Secret.
	 * @param masterSalt          the OSCORE Master Salt.
	 * @param groupIdPrefixSize   the size in bytes of the Prefix part of the OSCORE Group ID. Up to 4 bytes.
	 * @param groupIdPrefix       the Prefix part of the OSCORE Group ID.
	 * @param groupIdEpochSize    the size in bytes of the byte array representation of the Epoch part of the OSCORE Group ID. Up to 4 bytes.
	 * @param groupIdEpoch        the current value of the Epoch part of the OSCORE Group ID as a positive integer.
	 * @param senderIdSize        the size in bytes of Sender IDs in the OSCORE Group. Up to 4 bytes, same for all Sender IDs in the OSCORE group.
	 * @param alg                 the AEAD algorithm used in the OSCORE group.
	 * @param hkdf                the HKDF used in the OSCORE group.
	 * @param csAlg               the countersignature algorithm used in the OSCORE group.
	 * @param csParams            the parameters of the countersignature algorithm used in the OSCORE group.
	 * @param csKeyParams         the parameters of the key for the countersignature algorithm used in the OSCORE group.
	 * @param csKeyEnc            the encoding of the key for the countersignature algorithm used in the OSCORE group.
	 * @param groupPolicies		  the map of group policies used in the OSCORE group, or Null for building one with default values
	 */
    public GroupInfo(final String groupName,
    				 final byte[] masterSecret,
    				 final byte[] masterSalt,
    				 final int groupIdPrefixSize,
    		         final byte[] groupIdPrefix,
    		         final int groupIdEpochSize,
    		         final int groupIdEpoch,
    		         final String prefixMonitorNames,
    		         final int senderIdSize,
    		         final AlgorithmID alg,
    		         final AlgorithmID hkdf,
    		         final AlgorithmID csAlg,
    		         final CBORObject csParams,
    		         final CBORObject csKeyParams,
    		         final CBORObject csKeyEnc,
    		         final CBORObject groupPolicies) {
    	
    	this.version = 0;
    	this.status = false;
    	
    	setGroupName(groupName);
    	
    	setMasterSecret(masterSecret);
    	setMasterSalt(masterSalt);
    	
    	this.groupIdPrefixSize = groupIdPrefixSize;
    	setGroupIdPrefix(groupIdPrefix);
    	setGroupIdEpoch(groupIdEpochSize, groupIdEpoch);
    	
    	this.prefixMonitorNames = prefixMonitorNames;
    	
    	setAlg(alg);
    	setHkdf(hkdf);
    	setCsAlg(csAlg);
    	setCsParams(csParams);
    	setCsKeyParams(csKeyParams);
    	setCsKeyEnc(csKeyEnc);
    	
    	if (senderIdSize < 1)
    		this.senderIdSize = 1;
    	else if (senderIdSize > 4)
    		this.senderIdSize = 4;
    	else
    		this.senderIdSize = senderIdSize;
    	
    	if (senderIdSize == 4)
    		this.maxSenderIdValue = (1 << 31) - 1;
    	else
    		this.maxSenderIdValue = (1 << (senderIdSize * 8)) - 1;
    	
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedSenderIds.add(new HashSet<Integer>());
    		
        	// Empty sets of stored public keys; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		publicKeyRepo.add(new HashMap<Integer, CBORObject>());
    		
        	// Empty sets of roles; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		nodeRoles.add(new HashMap<Integer, Integer>());
    		
    	}
    	
    	this.groupPolicies = groupPolicies;
    	
    	if (groupPolicies == null) {
    		// Set default policy values
        	CBORObject defaultGroupPolicies = CBORObject.NewMap();
        	defaultGroupPolicies.Add(Constants.POLICY_SN_SYNCH, CBORObject.FromObject(1));
        	defaultGroupPolicies.Add(Constants.POLICY_KEY_CHECK_INTERVAL, CBORObject.FromObject(3600));
        	defaultGroupPolicies.Add(Constants.POLICY_EXP_DELTA, CBORObject.FromObject(0));
        	defaultGroupPolicies.Add(Constants.POLICY_PAIRWISE_MODE, CBORObject.False);
        	this.groupPolicies = defaultGroupPolicies;
    	}
    	
    }
    
    /** Retrieve the current status of the group
     * 
     * @return  True if the group is currently active, false otherwise
     */
    synchronized public final boolean getStatus() {
    	
    	return this.status;
    	
    }
    
    /** 
     * Set the status of the group
     * @param The new status to set for the group, i.e. true for active, false for inactive
     */
    synchronized public void setStatus(final boolean status) {
    	
    	this.status = status;
    	
    }
    
    /** Retrieve the OSCORE Master Secret value
     * 
     * @return  the master secret
     */
    synchronized public final byte[] getMasterSecret() {
    	
    	byte[] myArray = new byte[this.masterSecret.length];
    	System.arraycopy(this.masterSecret, 0, myArray, 0, this.masterSecret.length);
    	return myArray;
    	
    }
    
    /** 
     * Set the OSCORE Master Secret value
     * @param masterSecret
     */
    synchronized public void setMasterSecret(final byte[] masterSecret) {
    	
    	this.masterSecret = new byte[masterSecret.length];
    	System.arraycopy(masterSecret, 0, this.masterSecret, 0, masterSecret.length);
    	
    }
    
    /** Retrieve the name of the OSCORE group
     * @return  the name of the OSCORE group
     */
    synchronized public final String getGroupName() {
    	
    	return new String(this.groupName); 
    	
    }
    
    /** 
     * Set the name of the OSCORE group
     * @param groupName
     */
    synchronized public void setGroupName(final String groupName) {
    	
    	this.groupName = new String(groupName);
    	
    }
    
    /**
     *  Retrieve the OSCORE Master Salt value
     * @return  the master salt
     */
    synchronized public final byte[] getMasterSalt() {
    	
    	byte[] myArray = new byte[this.masterSalt.length];
    	System.arraycopy(this.masterSalt, 0, myArray, 0, this.masterSalt.length);
    	return myArray;
    	
    }
    
    /**
     * Set the OSCORE Master Salt value
     * @param masterSalt
     */
    synchronized public void setMasterSalt(final byte[] masterSalt) {
    	
    	if (masterSalt == null) {
			this.masterSalt = new byte[0];
    	}
    	else {
    		this.masterSalt = new byte[masterSalt.length];
    		System.arraycopy(masterSalt, 0, this.masterSalt, 0, masterSalt.length);
    	}
    	
    }
    
    /**
     *  Get the Group ID Prefix as byte array
     * @return  the Group ID Prefix
     */
    synchronized public final byte[] getGroupIdPrefix() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length];
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	return myArray;
    	
    }
    
    /**
     *  Set the Group ID Prefix.
     * @param groupIdPrefix
     * @return false in case of error, or true otherwise.
     */
    synchronized public boolean setGroupIdPrefix(final byte[] groupIdPrefix) {
    	
    	if (groupIdPrefix.length != this.groupIdPrefixSize)
    		return false;
    	
    	this.groupIdPrefix = new byte[groupIdPrefix.length];
    	System.arraycopy(groupIdPrefix, 0, this.groupIdPrefix, 0, groupIdPrefix.length);
    	return true;
    	
    }
    
    /**
     *  Retrieve the Group ID Epoch value as an integer
     * @return  the Group ID Epoch
     */
    synchronized public final int getGroupIdEpoch() {
    	
    	return this.groupIdEpoch;
    	
    }
    
    // Set the size and initial value of the Group ID Epoch.
    // This method is only internally invoked by this class' constructor.
    //
    // Return false in case of invalid input parameters, or true otherwise.
    synchronized private boolean setGroupIdEpoch(final int groupIdEpochSize, final int groupIdEpoch) {
    	
    	if (groupIdEpochSize < 1)
    		return false;
    	else if (groupIdEpochSize > 4)
    		return false;
    	else
    		this.groupIdEpochSize = groupIdEpochSize;
    	
    	this.groupIdEpoch = groupIdEpoch;
    	this.maxGroupIdEpochValue = (1 << (groupIdEpochSize * 8)) - 1;

    	return true;
    }

    /**
     *  Set an arbitrary new value of the Group ID Epoch.
     * @param groupIdEpoch
     * @return  false in case of invalid input parameters, or true otherwise.
     */
    synchronized public boolean setGroupIdEpoch(final int groupIdEpoch) {

        // The Group ID Epoch can only grow
        if (groupIdEpoch <= this.groupIdEpoch)
            return false;

        if (groupIdEpoch > this.maxGroupIdEpochValue)
            return false;

        this.groupIdEpoch = groupIdEpoch;
        return true;

    }

    /**
     *  Increment the value of the Group ID Epoch.
     * @return  false if the maximum value is passed, or true otherwise.
     */
    synchronized public boolean incrementGroupIdEpoch() {

        boolean ret = false;

        // This should trigger a group rekeying
        if (this.groupIdEpoch == this.maxGroupIdEpochValue)
            this.groupIdEpoch = 0;

        else {
            this.groupIdEpoch++;
            ret = true;
        }
    	
    	return ret;
    	
    }
    
    /**
     * @return  the full {Prefix + Epoch} Group ID as a Byte Array
     */
    synchronized public final byte[] getGroupId() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length + this.groupIdEpochSize];
    	for (int i = 0; i < myArray.length; i++)
    		myArray[i] = (byte) 0x00;
    	
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	
    	// The returned array has the minimal size to represent integer, hence the possible padding with zeros
    	byte[] groupIdEpochArray = intToBytes(this.groupIdEpoch);
    	
    	if (groupIdEpochArray.length == 0 || groupIdEpochArray.length > this.groupIdEpochSize)
    		return null;
    		    	
    	int diff = this.groupIdEpochSize - groupIdEpochArray.length;
    	System.arraycopy(groupIdEpochArray, 0, myArray, this.groupIdPrefix.length + diff, groupIdEpochArray.length);
    	     
    	return myArray;
    	
    }
    
    /**
     * @return the AEAD algorithm used in the group
     */
    synchronized public final AlgorithmID getAlg() {
    	
    	return this.alg;
    	
    }
    
    /**
     *  Set the AEAD algorithm used in the group
     * @param alg
     */
    synchronized public void setAlg(final AlgorithmID alg) {
    	
    	if (alg == null)
			this.alg = AlgorithmID.AES_CCM_16_64_128;
    	else
    		this.alg = alg;
    	
    }
    
    /**
     * @return the KDF used in the group
     */
    synchronized public final AlgorithmID getHkdf() {
    	
    	return this.hkdf;
    	
    }
    
    /**
     *  Set the KDF used in the group
     * @param hkdf
     */
    synchronized public void setHkdf(final AlgorithmID hkdf) {
    	
    	if (hkdf == null)
    		this.hkdf = AlgorithmID.HKDF_HMAC_SHA_256;
    	else
    		this.hkdf = hkdf;
    	
    }
    
    /**
     * @return  the countersignature algorithm used in the group
     */
    synchronized public final AlgorithmID getCsAlg() {
    	
    	return this.csAlg;
    	
    }
    
    /**
     *  Set the countersignature algorithm used in the group
     * @param csAlg
     */
    synchronized public void setCsAlg(final AlgorithmID csAlg) {
    	
    	if (csAlg == null)
    		this.csAlg = AlgorithmID.EDDSA;
    	else
    		this.csAlg = csAlg;
    	
    }    
    
    /**
     * @return  the countersignature algorithm used in the group
     */
    synchronized public final CBORObject getCsParams() {
    	
    	return this.csParams;
    	
    }

    /**
     * Set the countersignature parameters used in the group
     * @param csParams
     * 
     * @return true of the parameters were successfully set, false otherwise
     */
    synchronized public boolean setCsParams(final CBORObject csParams) {

    	if (csParams.getType() != CBORType.Array)
    		return false;
    	
    	this.csParams = csParams;
    	
    	return true;
    	
    }
    
    /**
     * @return parameters of the key of the countersignature key 
     *      used in the group
     */
    synchronized public final CBORObject getCsKeyParams() {
    	
    	return this.csKeyParams;
    	
    }
    
    /**
     *  Set the parameters of the key of the countersignature key used
     *   in the group
     * @param csKeyParams  the parameters
     * @return  true if the parameters were successfully set, false otherwise
     */
    synchronized public boolean setCsKeyParams(final CBORObject csKeyParams) {
    
    	if (csKeyParams.getType() != CBORType.Array)
    		return false;
    	
    	this.csKeyParams = csKeyParams;
    	return true;
    	
    }
    
    /**
     * @return encoding of the key of the countersignature algorithm 
     *      used in the group
     */
    synchronized public final CBORObject getCsKeyEnc() {
    	
    	return this.csKeyEnc;
    	
    }
    
    /**
     *  Set the encoding of the key of the countersignature algorithm used
     *   in the group
     * @param csKeyEnc  the encoding
     * @return  true if the encoding was successfully set, false otherwise
     */
    synchronized public boolean setCsKeyEnc(final CBORObject csKeyEnc) {
    	
        //XXX: Is this Integer or SimpleValue?
    	if (csKeyEnc.getType() != CBORType.Integer)
    		return false;
    	
    	this.csKeyEnc = csKeyEnc;
    	return true;
    	
    }

    /**
     *  Return the whole collection of Sender IDs assigned so far.
     *  Note that this includes also Sender IDs of members that have left the group.
     *  On top of uniqueness, there is not re-cycling of previously assigned Sender IDs.
     * @return   The whole collection of assigned Sender IDs.
     */
    synchronized public List<Set<Integer>> getUsedSenderIds() {
    	
    	return this.usedSenderIds;
    	
    }
    
    /**
     * Find the first available Sender ID value and allocate it.
     * @return  the allocated Sender ID value as a byte array, or null if all values are used.
     */
    synchronized public byte[] allocateSenderId() {
    	
    	// All the possible values for the Sender IDs with this size have been allocated.
    	// Switch to the next size, up to 4 bytes, and update the maximum Sender ID value.
    	if (this.usedSenderIds.get(this.senderIdSize - 1).size() == (this.maxSenderIdValue + 1)) {
	    		this.senderIdSize++;
	    
        	// All Sender IDs with all possible sizes have been assigned already
        	if (this.senderIdSize > 4)
        		return null;
        	
        	if (senderIdSize == 4)
        		this.maxSenderIdValue = (1 << 31) - 1;
        	else
        		this.maxSenderIdValue = (1 << (senderIdSize * 8)) - 1;
    	}
    	
    	byte[] senderIdByteArray = null;
    	for (int i = 0; i <= this.maxSenderIdValue; i++) {
    		if (!this.usedSenderIds.get(senderIdSize - 1).contains(i)) {
    			this.usedSenderIds.get(senderIdSize - 1).add(i);
    			
    			senderIdByteArray = new byte[this.senderIdSize];
    			for (int j = 0; j < senderIdByteArray.length; j++)
    				senderIdByteArray[j] = (byte) 0x00;
    			
    			// The returned array has the minimal size to represent the integer value, hence the possible padding with zeros
    			byte[] myArray = intToBytes(i);
    			int diff = senderIdByteArray.length - myArray.length;
    			
    			System.arraycopy(myArray, 0, senderIdByteArray, diff, myArray.length);
    			break;
    		}
    	}
    	
    	return senderIdByteArray;
    	
    }
    
    /**
     *  If never assigned before, assign a particular Sender ID value provided as byte array.
     * @param id   The requested Sender ID to allocate
     * @return   True is the Sender ID could be allocated, false otherwise.
     */
    synchronized public boolean allocateSenderId(byte[] id) {
    	
    	if (id.length != this.senderIdSize)
    		return false;
    	
    	// All the possible values for the Sender IDs with this size have been assigned already
    	if (this.usedSenderIds.get(this.senderIdSize - 1).size() == (this.maxSenderIdValue + 1))
    		return false;
    	
    	// The specified Sender ID has been already assigned - And no recycling is admitted
    	if (this.usedSenderIds.get(this.senderIdSize - 1).contains(bytesToInt(id)))
    		return false;
    	
    	// In case the input array is 4 bytes in size and encoding a negative integer, this will return false
    	return allocateSenderId(bytesToInt(id));
    	
    }
    
    /**
     *  Check if a particular Sender ID value provided as an integer is available.
     * @param id
     * @return  if available allocate it and return true. Otherwise, return false.
     */
    synchronized private boolean allocateSenderId(final int id) {
    	
    	if (id < 0 || id > this.maxSenderIdValue)
    		return false;
    	
    	if (!this.usedSenderIds.get(senderIdSize - 1).contains(id)) {
    		this.usedSenderIds.get(senderIdSize - 1).add(id);
    		return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     * Release a particular Sender ID value provided as a byte array.
     * 
     * This method is intended only to rollback from errors during the joining process.
     * 
     * @param idByteArray   The Sender ID as byte array
     * @return  false in case of failure, true otherwise.
     */
    synchronized public boolean deallocateSenderId(final byte[] idByteArray) {
    	
    	if (idByteArray.length != this.senderIdSize)
    		return false;
    	
    	int id = bytesToInt(idByteArray);
    	
    	// In case the input array is 4 byte in size and encoding a negative integer, this will return false
    	return deallocateSenderId(id, idByteArray.length);
    	
    }
    
    /**
     * Release a particular Sender ID value provided as an integer.
     * 
     * This method is intended only to rollback from errors during the joining process.
     *  
     * @param id   the Sender ID converted to integer
     * @param size   the size in bytes of the original Sender ID as byte array
     * @return  false in case of failure, or true otherwise.
     */
    synchronized private boolean deallocateSenderId(final int id, final int size) {

    	if (size < 0 || size > 4)
    		return false;
    	
    	int maxValue;
    	
    	if (size == 4)
    		maxValue = (1 << 31) - 1;
    	else
    		maxValue = (1 << (senderIdSize * 8)) - 1;
    	
    	if (id < 0 || id > maxValue)
    		return false;
    	
    	if (this.usedSenderIds.get(size - 1).contains(id)) {
    		this.usedSenderIds.get(size - 1).remove(id);
			return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     * Assign a node name to group member. If applicable, the group member must have already received a Sender ID.
     * 
     * @param id   The Sender ID already assigned to the node. It is Null if the node is a monitor.
     * @return   The name assigned to the group member, or Null if there was a problem.
     */
    synchronized public String allocateNodeName(byte[] id) {
    	
    	String nodeName = null;
    	
    	// The group member is a monitor and gets a node name following a monitor-name schema
    	if (id == null) {
        	int maxSuffixValue = (1 << 31) - 1;
    		for (int i = 0; i <= maxSuffixValue; i++) {
    			// This suffix value has been already assigned - No recycling is admitted
    			if (suffixMonitorNames.contains(Integer.valueOf(i))) {
    				continue;
    			}
    			else {
    				// Mark the suffix value as assigned
    				suffixMonitorNames.add(Integer.valueOf(i));
    				nodeName = new String(prefixMonitorNames + String.valueOf(i));
    				break;
    			}
    		}
    	}
    	// The group member is not a monitor and has already been assigned a Sender ID
    	else {
	    	// Double-check that the specified Sender ID has been in fact allocated
	    	if (this.usedSenderIds.get(this.senderIdSize - 1).contains(bytesToInt(id)))
	    		nodeName = new String(Utils.bytesToHex(id));
    	}
    	
    	return nodeName;
    	
    }
    
    /**
     * Release a particular node name previously assigned to a node joining the group as monitor.
     * 
     * This method is intended only to rollback from errors during the joining process,
     * and only for candidate members attempting to join the group as monitor.
     * 
     * @param nodeName   The node name as a string
     */
    synchronized public void deallocateNodeName(final String nodeName) {
    	
    	// Double-check that the node name is consistent with the naming schema for monitor group members
    
    	int prefixSize = prefixMonitorNames.length();
    	if (nodeName.length() < (prefixMonitorNames.length() + 1))
    		return;
    	if(!nodeName.substring(0, prefixSize).equals(prefixMonitorNames))
    		return;
    	for (int i = prefixSize; i < nodeName.length(); i++) {
    		if (!Character.isDigit(nodeName.charAt(i)))
    			return;
    	}
    	
    	String valueStr = nodeName.substring(prefixSize, nodeName.length());
    	int value = Integer.parseInt(valueStr);
    	
    	suffixMonitorNames.remove(Integer.valueOf(value));
    	
    }
    
    /**
     * Check if a certain node is a current group member
     * 
     * @param subject   The identity of the node, as per its secure association with the Group Manager
     * @return   True if the node is a current member of the group, false otherwise
     */
    synchronized public boolean isGroupMember(final String subject) {

    	return this.identities2nodeNames.containsKey(subject);
    		
    }
    
    /**
     * Add a new group member - Note that the public key has to be added separately
     * 
     * @param sid   The Sender ID of the new node. It is Null if the node is a monitor.
     * @param sid   The node name of the new node.
     * @param roles   The role(s) of the new node, encoded in the AIF data model
     * @param subject   The node's identity based on the secure association with the GM
     * @return   True if the node is successfully added to the group, false otherwise
     */
    synchronized public boolean addGroupMember(final byte[] sid, final String name, final int roles, final String subject) {

    	// The node is a monitor
    	if (sid == null) {
    		if (roles != (1 << Constants.GROUP_OSCORE_MONITOR))
    			return false;
    	}
    	// THe node is not a monitor
    	else {
    		if (roles == (1 << Constants.GROUP_OSCORE_MONITOR))
    			return false;
	    	// Consider the inner map related to the size in bytes of the Sender ID
	    	this.nodeRoles.get(sid.length - 1).put(bytesToInt(sid), roles);
    	}
    	
    	this.identities2nodeNames.put(subject, name);
    	
    	return true;
    	
    }
    
    /**
     * Return the identity of the group member identified by the specified node name
     * 
     * @param subject   The identity of the node, as per its secure association with the Group Manager
     * 
     * @return The node name of the group member, of null if no member is found with the specified identity
     */
    synchronized public String getGroupMemberName(final String subject) {
    	
    	if (!this.identities2nodeNames.containsKey(subject))
    		return null;
    	
    	return this.identities2nodeNames.get(subject);
    	
    }
    
    /**
     * Return the roles of the group member identified by the specified node name
     * 
     * @param nodeName   The node name of the group member
     * 
     * @return The roles of the group member encoded in the AIF data model
     */
    synchronized public short getGroupMemberRoles(final String nodeName) {
    	
    	// First, check if the node is a monitor, based on the naming-schema
    	int prefixSize = prefixMonitorNames.length();
    	if (nodeName.length() > (prefixMonitorNames.length()) &&
    		nodeName.substring(0, prefixSize).equals(prefixMonitorNames)) {
    		
    		return 1 << Constants.GROUP_OSCORE_MONITOR;
    		
    	}

    	// The node is not a monitor and has a Sender ID
    	byte[] sid = Utils.hexToBytes(nodeName);
    	
    	return getGroupMemberRoles(sid);
    	
    }
    
    /**
     * Return the roles of the group member identified by the specified Sender ID
     * 
     * @param sid   The Sender ID of the group member
     * 
     * @return The roles of the group member, encoded in the AIF data model
     */
    synchronized public short getGroupMemberRoles(final byte[] sid) {
    	
    	return this.nodeRoles.get(sid.length - 1).get(bytesToInt(sid)).shortValue();
    	
    }
        
    /**
     * Remove the group member identified by the specified identity
     * 
     * Note that the public key has to be removed separately
     * Note that the Sender ID is not deallocated, to ensure non-reassignment to future group members
     * 
     * @param subject   The node's identity based on the secure association with the GM 
     * @return True if an entry for the group member was found and removed, false otherwise
     */
    synchronized public boolean removeGroupMemberBySubject(final String subject) {
    	
    	if (!this.identities2nodeNames.containsKey(subject))
        		return false;
    	
    	String nodeName = this.identities2nodeNames.get(subject);
    	byte[] sid = Utils.hexToBytes(nodeName);
    	
    	if (!this.nodeRoles.get(sid.length - 1).containsKey(bytesToInt(sid)))
    		return false;
    	
    	this.nodeRoles.get(sid.length - 1).remove(bytesToInt(sid));
    	this.identities2nodeNames.remove(subject);
    	
    	return true;
    	
    }
    
    /**
     * Return the public keys of the current group members
     * 
     * @return  The set of public keys of the current group member with Sender ID 'sid' from the public key repo.
     */
    // The format of the public key is the raw CBOR Map encoding it as COSE Key. 
    synchronized public Set<CBORObject> getPublicKeys() {
    	
    	Set<CBORObject> publicKeys = new HashSet<>();
    	
    	// Go through each size of Sender ID, i.e. from 1 (i=0) to 4 (i=3) bytes
    	for (int i = 0; i < this.publicKeyRepo.size(); i++) {
    		
    		// Retrieve each public key
    		for (Map.Entry<Integer, CBORObject> pair : publicKeyRepo.get(i).entrySet()) {
    			publicKeys.add(pair.getValue());
    		}
    		
    	}
    	
    	return publicKeys;
    	
    }
    
    /**
     * Return the public key of the group member indicated by the provided Sender ID
     * 
     * @param sid   Sender ID of the group member associated to the public key.
     * @return  the public key 'key' of the group member.
     */
    // The format of the public key is the raw CBOR Map encoding it as COSE Key. 
    synchronized public CBORObject getPublicKey(final byte[] sid) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return null;
    	
    	return this.publicKeyRepo.get(sid.length - 1).get(bytesToInt(sid));
    	
    }
    
    /**
     *  Add the public key 'key' of the group member with Sender ID 'sid' to the public key repo.
     *  The format of the public key is the raw CBOR Map enconding it as COSE Key. 
     * @param sid
     * @param key
     * @return  true if it worked, false if it failed
     */
    synchronized public boolean storePublicKey(final byte[] sid, final CBORObject key) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return false;
    	
    	if (key.getType() != CBORType.Map)
    		return false;
    	
    	this.publicKeyRepo.get(sid.length - 1).put(bytesToInt(sid), key);
    	
    	return true;
    	
    }
    

    /**
     *  Remove the public key of the group member indicated by the provided Sender ID
     *  The format of the public key is the raw CBOR Map encoding it as COSE Key. 
     *  
     * @param sid   Sender ID of the group member associated to the public key.
     * @return  True if the public key was found and removed, false otherwise
     */
    synchronized public boolean deletePublicKey(final byte[] sid) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return false;
    	
    	if (!this.publicKeyRepo.get(sid.length - 1).containsKey(bytesToInt(sid)))
    		return false;
    	
    	this.publicKeyRepo.get(sid.length - 1).remove(bytesToInt(sid));
    	
    	return true;
    	
    }
    
    /**
     *  Return the current version of the symmetric keying material
	 *
	 *  @return  an integer indicating the current version of the symmetric keying material
     */
    synchronized public int getVersion() {
    	
    	return this.version;
    	
    }
    
    /**
     *  Increment the version of the symmetric keying material 
	 *
     */
    synchronized public void incrementVersion() {
    	
    	this.version++;
    	
    }
    
    /**
     *  Return the group policies
	 *
	 *  @return  a CBOR map including the group policies
     */
    synchronized public CBORObject getGroupPolicies() {
    	
    	return this.groupPolicies;
    	
    }
    
    /**
     *  Return the current size of new Sender IDs to assign
	 *
	 *  @return  an integer with the current size of new Sender IDs to assign 
     */
    synchronized public int getSenderIdSize() {
    	
    	return this.senderIdSize;
    	
    }
    
    /**
     *  Convert a positive integer into a byte array of minimal size.
     *  The positive integer can be up to 2,147,483,647 
     * @param num
     * @return  the byte array
     */
    public static byte[] intToBytes(final int num) {

    	// Big-endian
    	if (num < 0)
    		return null;
        else if (num < 256) {
            return new byte[] { (byte) (num) };
        } else if (num < 65536) {
            return new byte[] { (byte) (num >>> 8), (byte) num };
        } else if (num < 16777216) {
            return new byte[] { (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        } else { // up to 2,147,483,647
            return new byte[]{ (byte) (num >>> 24), (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        }
    	
    	// Little-endian
    	/*
    	if (num < 0)
    		return null;
        else if (num < 256) {
            return new byte[] { (byte) (num) };
        } else if (num < 65536) {
            return new byte[] { (byte) num, (byte) (num >>> 8) };
        } else if (num < 16777216){
            return new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16) };
        } else{ // up to 2,147,483,647
            return new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16), (byte) (num >>> 24) };
        }
    	*/
    	
    }

    /**
     * Convert a byte array into an equivalent unsigned integer.
     * The input byte array can be up to 4 bytes in size.
     *
     * N.B. If the input array is 4 bytes in size, the returned integer may be negative! The calling method has to check, if relevant!
     * 
     * @param bytes 
     * @return   the converted integer
     */
    public static int bytesToInt(final byte[] bytes) {
    	
    	if (bytes.length > 4)
    		return -1;
    	
    	int ret = 0;

    	// Big-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[bytes.length - 1 - i] & 0xFF) * (int) (Math.pow(256, i));

    	/*
    	// Little-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[i] & 0xFF) * (int) (Math.pow(256, i));
    	*/
    	
    	return ret;
    	
    }
    
}
