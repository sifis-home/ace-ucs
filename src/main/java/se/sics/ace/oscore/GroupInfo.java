 /*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;

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
	private Set<Integer> usedSenderIds = new HashSet<Integer>();
	private Set<Integer> freeSenderIds = new HashSet<Integer>();
	private byte[] groupIdPrefix;
	private int groupIdEpoch = 0;
	private AlgorithmID alg;
	private AlgorithmID hkdf;
	private AlgorithmID csAlg;
	private CBORObject csParams;
	
	private int groupIdEpochSize;     // Epoch size (bytes) in the {Prefix ; Epoch} Group ID
	private int maxGroupIdEpochValue;
	
	private int senderIdSize;     // Sender ID size (bytes)
	private int maxSenderIdValue;
	
	/**
	 * Creates a new OSCORE GroupInfo object.
	 * 
	 * @param myMap  the map of parameters.
	 */
    public GroupInfo(final byte[] masterSecret,
    				 final byte[] masterSalt,
    		         final byte[] groupIdPrefix,
    		         final int groupIdEpochSize,
    		         final int senderIdSize,
    		         final AlgorithmID alg,
    		         final AlgorithmID hkdf,
    		         final AlgorithmID csAlg,
    		         final CBORObject csParams) {
    	
    	setMasterSecret(masterSecret);
    	setMasterSalt(masterSalt);
    	setGroupIdPrefix(groupIdPrefix);
    	
    	if (groupIdEpochSize < 1)
    		this.groupIdEpochSize = 1;
    	else if (groupIdEpochSize > 4)
    		this.groupIdEpochSize = 4;
    	else
    		this.groupIdEpochSize = groupIdEpochSize;
    	
    	if (groupIdEpochSize == 4)
    		maxGroupIdEpochValue = (2 << 31) - 1;
    	else
    		maxGroupIdEpochValue = (2 << (groupIdEpochSize * 8)) - 1;
    	
    	if (senderIdSize < 1)
    		this.senderIdSize = 1;
    	else if (senderIdSize > 4)
    		this.senderIdSize = 4;
    	else
    		this.senderIdSize = senderIdSize;
    	
    	if (senderIdSize == 4)
    		maxSenderIdValue = (2 << 31) - 1;
    	else
    		maxSenderIdValue = (2 << (senderIdSize * 8)) - 1;
    	
    	for (int i = 0; i < maxSenderIdValue; i++) {
    		freeSenderIds.add(i);
    	}
    	
    	setAlg(alg);
    	setHkdf(hkdf);
    	setCsAlg(csAlg);
    	setCsParams(csParams);
    	
    }
    
    synchronized public final byte[] getMasterSecret() {
    	
    	byte[] myArray = new byte[this.masterSecret.length];
    	System.arraycopy(this.masterSecret, 0, myArray, 0, this.masterSecret.length);
    	return myArray;
    	
    }
    
    synchronized public void setMasterSecret(final byte[] masterSecret) {
    	
    	this.masterSecret = new byte[masterSecret.length];
    	System.arraycopy(masterSecret, 0, this.masterSecret, 0, masterSecret.length);
    	
    }
    
    synchronized public final byte[] getMasterSalt() {
    	
    	byte[] myArray = new byte[this.masterSalt.length];
    	System.arraycopy(this.masterSecret, 0, myArray, 0, this.masterSecret.length);
    	return myArray;
    	
    }
    
    synchronized public void setMasterSalt(final byte[] masterSalt) {
    	
    	if (masterSalt == null) {
			this.masterSalt = new byte[0];
    	}
    	else {
    		this.masterSalt = new byte[masterSalt.length];
    		System.arraycopy(masterSalt, 0, this.masterSalt, 0, masterSalt.length);
    	}
    	
    }
    
    synchronized public final byte[] getGroupIdPrefix() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length];
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	return myArray;
    	
    }
    
    synchronized public void setGroupIdPrefix(final byte[] groupIdPrefix) {
    	
    	this.groupIdPrefix = new byte[groupIdPrefix.length];
    	System.arraycopy(groupIdPrefix, 0, this.groupIdPrefix, 0, groupIdPrefix.length);
    	
    }
    
    synchronized public final int getGroupIdEpoch() {
    	
    	return groupIdEpoch;
    	
    }
    
    synchronized public void updateGroupIdEpoch() {
    	
    	if (this.groupIdEpoch == this.maxGroupIdEpochValue)
    		this.groupIdEpoch = 0;
    	else
    		this.groupIdEpoch++;
    	
    }
    
    synchronized public final byte[] getGroupId() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length + this.groupIdEpochSize];
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	System.arraycopy(intToBytes(groupIdEpoch), 0, myArray, this.groupIdPrefix.length, this.groupIdEpochSize);
    	return myArray;
    	
    }
    
    synchronized public final AlgorithmID getAlg() {
    	
    	return this.alg;
    	
    }
    
    synchronized public void setAlg(final AlgorithmID alg) {
    	
    	if (alg == null)
			this.alg = AlgorithmID.AES_CCM_16_64_128;
    	else
    		this.alg = alg;
    	
    }
    
    synchronized public final AlgorithmID getHkdf() {
    	
    	return this.hkdf;
    	
    }
    
    synchronized public void setHkdf(final AlgorithmID hkdf) {
    	
    	if (hkdf == null)
    		this.hkdf = AlgorithmID.EDDSA;
    	else
    		this.hkdf = hkdf;
    	
    }
    
    synchronized public final AlgorithmID getCsAlg() {
    	
    	return this.csAlg;
    	
    }
    
    synchronized public void setCsAlg(final AlgorithmID csAlg) {
    	
    	if (csAlg == null)
    		this.csAlg = AlgorithmID.EDDSA;
    	else
    		this.csAlg = csAlg;
    	
    }    
    
    synchronized public final CBORObject getCsParams() {
    	
    	return this.csParams;
    	
    }
    
    synchronized public void setCsParams(final CBORObject csParams) {
    	
    	if (csParams == null)
    		this.csParams = KeyKeys.OKP_Ed25519;
    	else
    		this.csParams = csParams;
    	
    }   

    synchronized public byte[] allocateSenderId() {
    	
    	if (this.freeSenderIds.isEmpty())
    		return null;
    	
    	byte[] senderIdByteArray = null;
    	for (int i = 0; i < this.maxSenderIdValue; i++) {
    		if (this.freeSenderIds.contains(i)) {
    			this.freeSenderIds.remove(i);
    			this.usedSenderIds.add(i);
    			senderIdByteArray = new byte[this.senderIdSize];
    			System.arraycopy(intToBytes(i), 0, senderIdByteArray, 0, this.senderIdSize);
    			break;
    		}
    	}
    	
    	return senderIdByteArray;
    	
    }
    
    private final byte[] intToBytes(final int i) {
        ByteBuffer bb = ByteBuffer.allocate(4); 
        bb.putInt(i); 
        return bb.array();
    }
    
}
