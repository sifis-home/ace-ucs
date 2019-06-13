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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;

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
	private byte[] masterSecret;
	private byte[] masterSalt;
	
	private Set<Integer> usedSenderIds = new HashSet<>();
	private int senderIdSize; // Size in bytes of the byte array representation of Sender IDs 
	private int maxSenderIdValue;
	
	// This map stores the public keys of the group members as COSE Keys (CBOR Maps).
	// The map key (label) is the integer representation of the Sender ID of the group member. 
	private Map<Integer, CBORObject> publicKeyRepo = new HashMap<>();
	
	private final int groupIdPrefixSize; // Prefix size (bytes), same for every Group ID on the same Group Manager
	private byte[] groupIdPrefix;
	
	private int groupIdEpochSize; // Epoch size (bytes) in the {Prefix ; Epoch} Group ID
	private int maxGroupIdEpochValue;
	private int groupIdEpoch;
	
	private AlgorithmID alg;
	private AlgorithmID hkdf;
	private AlgorithmID csAlg;
	private CBORObject csParams;
	
	/**
	 * Creates a new GroupInfo object tracking the current status of an OSCORE group.
	 * 
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
	 */
    public GroupInfo(final byte[] masterSecret,
    				 final byte[] masterSalt,
    				 final int groupIdPrefixSize,
    		         final byte[] groupIdPrefix,
    		         final int groupIdEpochSize,
    		         final int groupIdEpoch,
    		         final int senderIdSize,
    		         final AlgorithmID alg,
    		         final AlgorithmID hkdf,
    		         final AlgorithmID csAlg,
    		         final CBORObject csParams) {
    	
    	setMasterSecret(masterSecret);
    	setMasterSalt(masterSalt);
    	
    	this.groupIdPrefixSize = groupIdPrefixSize;
    	setGroupIdPrefix(groupIdPrefix);
    	setGroupIdEpoch(groupIdEpochSize, groupIdEpoch);
    	
    	setAlg(alg);
    	setHkdf(hkdf);
    	setCsAlg(csAlg);
    	setCsParams(csParams);
    	
    	if (senderIdSize < 1)
    		this.senderIdSize = 1;
    	else if (senderIdSize > 4)
    		this.senderIdSize = 4;
    	else
    		this.senderIdSize = senderIdSize;
    	
    	if (senderIdSize == 4)
    		this.maxSenderIdValue = (2 << 31) - 1;
    	else
    		this.maxSenderIdValue = (2 << (senderIdSize * 8)) - 1;
    	
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
    	
    	if (groupIdEpochSize == 4)
    		this.maxGroupIdEpochValue = (2 << 31) - 1;
    	else
    	    this.maxGroupIdEpochValue = (2 << (groupIdEpochSize * 8)) - 1;

    	this.groupIdEpoch = groupIdEpoch;

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
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	
    	byte[] groupIdEpochArray = intToBytes(this.groupIdEpoch);
    	
    	if (groupIdEpochArray.length != 0)
    		System.arraycopy(groupIdEpochArray, 0, myArray, this.groupIdPrefix.length, groupIdEpochArray.length);
    	
    	// Ensure that the Group ID Epoch have the intended size in bytes
    	int diff = this.groupIdEpochSize - groupIdEpochArray.length;
    	for (int i = 0; i < diff; i++) {
    		int offset = this.groupIdPrefix.length + groupIdEpochArray.length + i; 
    		myArray[offset] = (byte) 0x00;
    	}
    	
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
     */
    synchronized public void setCsParams(final CBORObject csParams) {
    
    	this.csParams = csParams;
    	
    }   

    /**
     * Find the first available Sender ID value and allocate it.
     * @return  the allocated Sender ID value as a byte array, or null if all values are used.
     */
    synchronized public byte[] allocateSenderId() {
    	
    	// All the possible values for the Sender IDs are used
    	if (this.usedSenderIds.size() == (this.maxSenderIdValue + 1))
    		return null;
    	
    	byte[] senderIdByteArray = null;
    	for (int i = 0; i < this.maxSenderIdValue; i++) {
    		if (!this.usedSenderIds.contains(i)) {
    			this.usedSenderIds.add(i);
    			senderIdByteArray = new byte[this.senderIdSize];
    			System.arraycopy(intToBytes(i), 0, senderIdByteArray, 0, this.senderIdSize);
    			break;
    		}
    	}
    	
    	return senderIdByteArray;
    	
    }
    
    /**
     *  Check if a particular Sender ID value provided as an integer is available.
     * @param id
     * @return  if available allocate it and return true. Otherwise, return false.
     */
    synchronized public boolean allocateSenderId(final int id) {
    	
    	// All the possible values for the Sender IDs are used
    	if (this.usedSenderIds.size() == (this.maxSenderIdValue + 1))
    		return false;
    	
    	if (id < 0 || id > this.maxSenderIdValue)
    		return false;
    	
    	if (!this.usedSenderIds.contains(id)) {
    		this.usedSenderIds.add(id);
    		return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     *  Check if a particular Sender ID value provided as a byte array is available.
     * @param id
     * @return   If available, allocate it and return true. Otherwise, return false.
     */
    synchronized public boolean allocateSenderId(byte[] id) {
    	
    	// All the possible values for the Sender IDs are used
    	if (this.usedSenderIds.size() == (this.maxSenderIdValue + 1))
    		return false;
    	
    	if (id.length != this.senderIdSize)
    		return false;
    	
    	// In case the input array is 4 byte in size and encoding a negative integer, this will return false
    	return allocateSenderId(bytesToInt(id));
    	
    }
    
    /**
     * @return  the set of allocated Sender Ids in the OSCORE group
     */
    synchronized public final Set<Integer> getUsedSenderIds() {
    	
    	return new HashSet<>(this.usedSenderIds);
    	
    }
    
    /**
     *  Release a particular Sender ID value provided as an integer.
     * @param id
     * @return  false in case of failure, or true otherwise.
     */
    synchronized public boolean deallocateSenderId(final int id) {
    	
    	if (id < 0 || id > this.maxSenderIdValue)
    		return false;
    	
    	if (this.usedSenderIds.contains(id)) {
    		this.usedSenderIds.remove(id);
			return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     *  Release a particular Sender ID value provided as an byte array.
     * @param idByteArray
     * @return  false in case of failure, or true otherwise.
     */
    synchronized public boolean deallocateSenderId(final byte[] idByteArray) {
    	
    	if (idByteArray.length != this.senderIdSize)
    		return false;
    	
    	int id = bytesToInt(idByteArray);
    	
    	// In case the input array is 4 byte in size and encoding a negative integer, this will return false
    	return deallocateSenderId(id);
    	
    }
    
    /**
     *  Add the public key 'key' of the group member with Sender ID 'sid' to the public key repo.
     *  The format of the public key is the raw CBOR Map enconding it as COSE Key. 
     * @param sid
     * @param key
     * @return  true if it worked, false if it failed
     */
    synchronized public boolean storePublicKey(final Integer sid, final CBORObject key) {
    	
    	if (!this.usedSenderIds.contains(sid))
    		return false;
    	
    	if (key.getType() != CBORType.Map)
    		return false;
    	
    	this.publicKeyRepo.put(sid, key);
    	
    	return true;
    	
    }
    
    /**
     * @param sid
     * @return  the public key 'key' of the group member with Sender ID 'sid' from the public key repo.
     */
    // The format of the public key is the raw CBOR Map enconding it as COSE Key. 
    synchronized public CBORObject getPublicKey(final Integer sid) {
    	
    	return this.publicKeyRepo.get(sid);
    	
    }

    /**
     *  Remove the public key 'key' of the group member with Sender ID 'sid' from the public key repo.
     *  The format of the public key is the raw CBOR Map enconding it as COSE Key. 
     *  
     * @param sid
     * @return  true if it was there, false if it wasn't
     */
    synchronized public boolean deletePublicKey(final Integer sid) {
    	
    	if (!this.publicKeyRepo.containsKey(sid))
    		return false;
    	
    	this.publicKeyRepo.remove(sid);
    	
    	return true;
    	
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
    	else if (num == 0) {
            return new byte[] {};
        } else if (num < 256) {
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
    	else if (num == 0) {
            return new byte[] {};
        } else if (num < 256) {
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
