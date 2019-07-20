/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.Collection;
import java.util.HashMap;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Base64;

import com.upokecenter.cbor.CBORObject;

/**
 * Group OSCORE Context. Inherits most functionality from the OSCORE Context in OSCoreCtx
 * 
 * Represents the Security Context and its parameters. At initiation derives the
 * keys and ivs. Also maintains replay window.
 *
 */
public class GroupOSCoreCtx extends OSCoreCtx {
	
	/**
	 * Enable or disable use of countersignatures.
	 * (Disabled will have counterisignature length 0)
	 */
	private final static boolean WITH_COUNTERSIGN = true;
	
	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	
	/**
	 * Class describing a recipient context (one Group OSCORE context will have many)
	 *
	 */
	@SuppressWarnings("unused")
	class RecipientCtx {
		public byte[] recipient_id;
		public byte[] recipient_key;
		public int recipient_seq;
		private int recipient_replay_window_size;
		private int recipient_replay_window;
		private byte[] context_id;
		private AlgorithmID common_alg;
		private int key_length;
		private AlgorithmID kdf;

		private int rollback_recipient_seq = -1;
		private int rollback_recipient_replay = -1;
		
		public OneKey recipient_public_key = null;
		
		/**
		 * Default constructor making a recipient context
		 * TODO: Have less parameters in signature
		 */
		public RecipientCtx(AlgorithmID alg, byte[] recipient_id, Integer replay_size, byte[] contextId,
				int keyLength, byte[] common_master_secret, byte[] common_master_salt, AlgorithmID kdf,
				OneKey recipient_public_key) {
		
			this.recipient_id = recipient_id.clone();
			this.recipient_seq = -1;
			this.recipient_replay_window_size = replay_size.intValue();
			this.recipient_replay_window = 0;
			this.context_id = contextId.clone();
			this.common_alg = alg;
			this.key_length = keyLength;
			this.kdf = kdf;
			
			this.recipient_public_key = recipient_public_key;
			
			String digest = null;
			switch (this.kdf) {
				case HKDF_HMAC_SHA_256:
					digest = "SHA256";
					break;
				case HKDF_HMAC_SHA_512:
					digest = "SHA512";
					break;
				case HKDF_HMAC_AES_128:
				case HKDF_HMAC_AES_256:
				default:
					System.err.println("Requested HKDF algorithm is not supported: " + this.kdf.toString());
			}
			
			// Derive recipient_key
			CBORObject info = CBORObject.NewArray();
			info.Add(this.recipient_id);
			info.Add(this.context_id);
			info.Add(this.common_alg.AsCBOR());
			info.Add(CBORObject.FromObject("Key"));
			info.Add(this.key_length);

			try {
				this.recipient_key = deriveKey(common_master_secret, common_master_salt, this.key_length, digest,
						info.EncodeToBytes());
			} catch (CoseException e) {
				System.err.println(e.getMessage());
			}
			
			//System.out.println("Key 2 " + Utils.toHexString(this.recipient_key));
		}
	}
	
	/**
	 * Group ID for Group OSCORE Group
	 */
	private byte[] groupId;
	
	/**
	 * Settings for the countersignature
	 */
	private AlgorithmID alg_countersign;
	private Integer par_countersign;
	
	/**
	 * Length of countersignature. Can depend on curve and algorithm.
	 */
	private int countersign_length;
	
	/**
	 * The private key of the sender (for countersignatures)
	 */
	private OneKey sender_private_key;
	
	/**
	 * Map of recipient contexts
	 * TODO: Rename map
	 */
	HashMap<String, RecipientCtx> hmap = new HashMap<String, RecipientCtx>();
	
	/**
	 * Constructor. Generates the context from the base parameters.
	 * 
	 * @param master_secret the master secret
	 * @param alg the encryption algorithm as defined in COSE
	 * @param client is this originally the client's context
	 * @param sender_id the sender id or null for default
	 * @param recipient_id the recipient id or null for default
	 * @param kdf the COSE algorithm abbreviation of the kdf or null for the
	 *            default
	 * @param replay_size the replay window size or null for the default
	 * @param master_salt the optional master salt, can be null
	 *
	 * @throws OSException if the KDF is not supported
	 */
	@SuppressWarnings("unused")
	public GroupOSCoreCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id,
			byte[] recipient_id, AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] groupId,
			AlgorithmID alg_countersign, Integer par_countersign, OneKey sender_private_key) throws OSException {
			
		//Call the constructor of OSCoreCtx
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, groupId);
		
		//Store the Group ID
		this.groupId = groupId;
		
		//Store settings for the countersignature
		this.alg_countersign = alg_countersign;
		this.par_countersign = par_countersign;	
		
		if(WITH_COUNTERSIGN == false) {
			countersign_length = 0;
			System.err.println("Warning: Not appending countersignatures!");
		} else if(alg_countersign == AlgorithmID.EDDSA && par_countersign == ED25519) {
			countersign_length = 64;
		} else if(alg_countersign == AlgorithmID.ECDSA_256) {
			countersign_length = 64;
		} else {
			System.err.println("Error: Unknown countersignature length!");
		}
		
		
		//Save private key of sender
		this.sender_private_key = sender_private_key;
				
		//Print information about the created context
		//Utility.printContextInfo(this);
	}
	
	//Rikard: Overloaded constructor without recipient id since they are added separately
	public GroupOSCoreCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] groupId,
			AlgorithmID alg_countersign, Integer par_countersign, OneKey sender_private_key) throws OSException {
		
		this(master_secret, client, alg, sender_id, null, kdf, replay_size, master_salt,
				groupId, alg_countersign, par_countersign, sender_private_key);
	}

	public byte[] getGroupId() {
		return groupId;
	}

	public AlgorithmID getAlgCountersign() {
		return alg_countersign;
	}

	public Integer getParCountersign() {
		return par_countersign;
	}
	
	/**
	 * Adds a recipient context for a certain recipient (without public key)
	 * @return 
	 */
	public void addRecipientContext(byte[] recipientId)
	{
		addRecipientContext(recipientId, null);
	}
	
	/**
	 * Adds a recipient context for a certain recipient with a public key for the recipient
	 * @return 
	 */
	public void addRecipientContext(byte[] recipientId, OneKey recipient_public_key)
	{
		RecipientCtx aCtx = new RecipientCtx(common_alg, recipientId, recipient_replay_window_size, 
				groupId, key_length, common_master_secret, common_master_salt, kdf, recipient_public_key);
		
		String index = Base64.encodeBytes(recipientId);	
		hmap.put(index, aCtx);
		
		//Print information about the recipient context
		//Utility.printRecipientContextInfo(aCtx);
	}
	
	/**
	 * @return get the recipient key for a certain recipient ID
	 */
	public byte[] getRecipientKey(byte[] recipient_id) {
		String index = Base64.encodeBytes(recipient_id);
		
		byte[] result = null; 
		
		if(hmap.get(index) != null) {
			result = (hmap.get(index)).recipient_key;
		}
		
		return result;
	}
	
	/**
	 * Enables setting the recipient key for a certain recipient ID
	 * 
	 * @param recipient_id the recipient ID to set the recipient key for
	 * @param recipientKey the recipient key to set
	 */
	public void setRecipientKey(byte[] recipient_id, byte[] recipientKey) {
		String index = Base64.encodeBytes(recipient_id);
		
		hmap.get(index).recipient_key = recipientKey.clone();
	}
	
	/**
	 * @return get the receiver sequence number for a certain recipient ID
	 */
	public synchronized int getReceiverSeq(byte[] recipient_id) {
		String index = Base64.encodeBytes(recipient_id);
		
		int result = -1; 
		
		if(hmap.get(index) != null) {
			result = (hmap.get(index)).recipient_seq;
		}
		
		return result;
	}
	
	//TODO: Implement considering replays and window
	public synchronized void checkIncomingSeq(int seq, byte[] recipient_id) throws OSException {
		String index = Base64.encodeBytes(recipient_id);
			
		if(hmap.get(index) != null) {
			(hmap.get(index)).recipient_seq = seq;;
		}
	}

	//Get the private key of the sender
	public OneKey getSenderPrivateKey() {
		return sender_private_key;
	}
	
	//Get the public key of a recipient for a certain recipient ID
	public OneKey getRecipientPublicKey(byte[] recipient_id) {
		String index = Base64.encodeBytes(recipient_id);
		
		return hmap.get(index).recipient_public_key;
	}

	//Return all recipient contexts from this Group context
	public Collection<RecipientCtx> getRecipientContexts() {
		return hmap.values();
	}

	/**
	 * @return the countersign_length
	 */
	public int getCountersignLength() {
		return countersign_length;
	}
	
	/** ---- Methods below should never be called on a Group OSCORE context ---- **/

	/**
	 * Enables setting the recipient key
	 * 
	 * @param recipientKey
	 */
	@Override
	public void setRecipientKey(byte[] recipientKey) {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to setRecipientKey on GroupOSCoreCtx" + stackTraceElements[2].toString());	
		super.setRecipientKey(recipientKey);
	}
	
	/**
	 * @param seq the recipient sequence number to set
	 */
	public synchronized void setReceiverSeq(int seq) {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to setReceiverSeq on GroupOSCoreCtx" + stackTraceElements[2].toString());
		super.setReceiverSeq(seq);
	}
	
	public int rollbackRecipientSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to rollbackRecipientSeq on GroupOSCoreCtx" + stackTraceElements[2].toString());
		return super.rollbackRecipientSeq();
	}

	public int rollbackRecipientReplay() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to rollbackRecipientReplay on GroupOSCoreCtx" + stackTraceElements[2].toString());
		return super.rollbackRecipientReplay();
	}
	
	/**
	 * @return the repipient's identifier
	 */
	public byte[] getRecipientId() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientId on GroupOSCoreCtx. " + stackTraceElements[2].toString());
				
		return super.getRecipientId();
	}
	
	/**
	 * @return get the receiver sequence number
	 */
	public synchronized int getReceiverSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getReceiverSeq on GroupOSCoreCtx" + stackTraceElements[2].toString());
		return super.getReceiverSeq();
	}
	
	/**
	 * @return get the recipient key
	 */
	public byte[] getRecipientKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientKey on GroupOSCoreCtx" + stackTraceElements[2].toString());
		return super.getRecipientKey();
	}
	
}
