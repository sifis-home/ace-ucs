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
package org.eclipse.californium.oscore.group;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import javax.crypto.KeyAgreement;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.oscore.ErrorDescriptions;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

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
	 * Enables or disables the optimized response functionality.
	 * If it is enabled responses no longer require a separate
	 * signature but rather use the encryption keys for source
	 * authentication. By default it is disabled.
	 */
	private boolean optimizedResponsesEnabled = false;
	
	/**
	 * Enable or disable use of countersignatures.
	 * (Disabled will have countersignature length 0)
	 */
	private final static boolean WITH_COUNTERSIGN = true;
	
	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value 6
	
	/**
	 * Do replay detection.
	 */
	public boolean REPLAY_CHECK = false;
	
	/**
	 * Class describing a recipient context (one Group OSCORE context will have many)
	 *
	 */
	@SuppressWarnings("unused")
	class RecipientCtx {
		public byte[] recipient_id;
		public byte[] recipient_key;
		public byte[] response_recipient_key;
		public int recipient_seq;
		private int recipient_replay_window_size;
		private int recipient_replay_window;
		private byte[] context_id;
		private AlgorithmID common_alg;
		private int key_length;
		private AlgorithmID kdf;

		private int rollback_recipient_seq = -1;
		private int rollback_recipient_replay = -1;
		private List<Integer> replay_window_list = new ArrayList<Integer>();
		
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
			
			if(recipient_public_key == null) {
				System.out.println("Info: Recipient added without public key.");
			}
			
			//If optimized responses are enabled and recipient has a public key.
			if(optimizedResponsesEnabled && recipient_public_key != null) {
				//First derive the response recipient key
				info = CBORObject.NewArray();
				info.Add(this.recipient_id);
				info.Add(this.context_id);
				info.Add(this.common_alg.AsCBOR());
				info.Add(CBORObject.FromObject("Key"));
				info.Add(this.key_length);
				
				System.out.println("For recipient ID " + Utils.toHexString(this.recipient_id));
				
				//Test adding KeyAgreement code
//				try {
//					//Seems Java 11 is needed for these
//					//https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyagreement-algorithms
//					//See also https://openjdk.java.net/jeps/324
//					KeyAgreement keyAgreement1 = KeyAgreement.getInstance("XDH");
//					KeyAgreement keyAgreement2 = KeyAgreement.getInstance("X448");
//					KeyAgreement keyAgreement3 = KeyAgreement.getInstance("X25519");
//				} catch (NoSuchAlgorithmException e1) {
//					// TODO Auto-generated catch block
//					e1.printStackTrace();
//				} catch (Exception e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
						
				byte[] sharedSecret = null;
				
				//FIXME: Generate shared secret correctly for EdDSA. Now it just uses the sender and recipient IDs.
				if(alg_countersign == AlgorithmID.EDDSA) {
					sharedSecret = ByteBuffer.allocate(8).putInt(Arrays.hashCode(this.recipient_id) + Arrays.hashCode(getSenderId())).array();	
				} else if(alg_countersign == AlgorithmID.ECDSA_256 || alg_countersign == AlgorithmID.ECDSA_384 || alg_countersign == AlgorithmID.ECDSA_512) { //ECDSA case
					sharedSecret = generateSharedSecretECDSA(sender_private_key, recipient_public_key);
				} else {
					System.err.println("Error: Unknown countersignature!");
				}
				
				try {
					this.response_recipient_key = deriveKey(this.recipient_key, sharedSecret, this.key_length, digest,
							info.EncodeToBytes());
					System.out.println("response_recipient_key " + Utils.toHexString(this.response_recipient_key));
				} catch (CoseException e) {
					System.err.println(e.getMessage());
				}
				
				//Then derive the response sender key (for this recipient) and add it to a list
				info = CBORObject.NewArray();
				info.Add(getSenderId());
				info.Add(this.context_id);
				info.Add(this.common_alg.AsCBOR());
				info.Add(CBORObject.FromObject("Key"));
				info.Add(this.key_length);
				
				try {
					byte[] response_sender_key = deriveKey(getSenderKey(), sharedSecret, this.key_length, digest,
							info.EncodeToBytes());
					System.out.println("response_sender_key " + Utils.toHexString(response_sender_key));
					addResponseSenderKey(this.recipient_id, response_sender_key);
				} catch (CoseException e) {
					System.err.println(e.getMessage());
				}
			}
			
			//System.out.println("Key 2 " + Utils.toHexString(this.recipient_key));
		}
		
		public boolean CheckReplay(int seq) {
			return replay_window_list.contains(seq);
		}
		
		public void AddSeq(int seq) {
			replay_window_list.add(seq);
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
	 * Map of response_sender_keys for recipients.
	 * Used for the optimized responses.
	 */
	HashMap<String, byte[]> response_sender_keys = new HashMap<String, byte[]>();
	
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
			System.err.println("Error: Unknown countersignature!");
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
	 * @return get the response recipient key for a certain recipient ID (for optimized responses)
	 */
	public byte[] getResponseRecipientKey(byte[] recipient_id) {
		String index = Base64.encodeBytes(recipient_id);
		
		byte[] result = null; 
		
		if(hmap.get(index) != null) {
			result = (hmap.get(index)).response_recipient_key;
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

	public synchronized void updateIncomingSeq(int seq, byte[] recipient_id) throws OSException {
		String index = Base64.encodeBytes(recipient_id);
		
		if(hmap.get(index) == null) {
			return;
		}

		if(REPLAY_CHECK) {
			(hmap.get(index)).AddSeq(seq);
			(hmap.get(index)).rollback_recipient_seq = (hmap.get(index)).recipient_seq;
			(hmap.get(index)).rollback_recipient_replay = (hmap.get(index)).recipient_replay_window;
			if (seq > (hmap.get(index)).recipient_seq) {
				// Update the replay window
				int shift = seq - (hmap.get(index)).recipient_seq;
				(hmap.get(index)).recipient_replay_window = (hmap.get(index)).recipient_replay_window << shift;
				(hmap.get(index)).recipient_seq = seq;
			} else if (seq == (hmap.get(index)).recipient_seq) {
				System.err.println("Sequence number is replay (Sequence number: " + seq + ")");
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			} else { // seq < recipient_seq
				if (seq + recipient_replay_window_size < (hmap.get(index)).recipient_seq) {
					System.err.println("Message too old");
					throw new OSException(ErrorDescriptions.REPLAY_DETECT);
				}
				// seq+replay_window_size > recipient_seq
				int shift = (hmap.get(index)).recipient_seq - seq;
				int pattern = 1 << shift;
				int verifier = (hmap.get(index)).recipient_replay_window & pattern;
				verifier = verifier >> shift;
				//if (verifier == 1) {
				//	throw new OSException(ErrorDescriptions.REPLAY_DETECT);
				//}
				(hmap.get(index)).recipient_replay_window = (hmap.get(index)).recipient_replay_window | pattern;
			}
		} else {
			
			if(hmap.get(index) != null) {
				(hmap.get(index)).recipient_seq = seq;;
			}
			
		}
	}
	
	public synchronized void checkIncomingSeq(int seq, byte[] recipient_id) throws OSException {
		String index = Base64.encodeBytes(recipient_id);
		
		if(hmap.get(index) == null) {
			return;
		}

		if(REPLAY_CHECK) {
			//(hmap.get(index)).rollback_recipient_seq = (hmap.get(index)).recipient_seq;
			//(hmap.get(index)).rollback_recipient_replay = (hmap.get(index)).recipient_replay_window;
			if (seq > (hmap.get(index)).recipient_seq) {
				// Update the replay window
				int shift = seq - (hmap.get(index)).recipient_seq;
				//(hmap.get(index)).recipient_replay_window = (hmap.get(index)).recipient_replay_window << shift;
				//(hmap.get(index)).recipient_seq = seq;
			} else if (seq == (hmap.get(index)).recipient_seq) {
				System.err.println("Sequence number is replay (Sequence number: " + seq + ")");
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			} else { // seq < recipient_seq
				if (seq + recipient_replay_window_size < (hmap.get(index)).recipient_seq) {
					System.err.println("Message too old");
					throw new OSException(ErrorDescriptions.REPLAY_DETECT);
				}
				// seq+replay_window_size > recipient_seq
				int shift = (hmap.get(index)).recipient_seq - seq;
				int pattern = 1 << shift;
				int verifier = (hmap.get(index)).recipient_replay_window & pattern;
				verifier = verifier >> shift;
				boolean check = (hmap.get(index)).CheckReplay(seq);
				if (check) {
					throw new OSException(ErrorDescriptions.REPLAY_DETECT);
				}
				//(hmap.get(index)).recipient_replay_window = (hmap.get(index)).recipient_replay_window | pattern;
			}
		} else {
			
//			if(hmap.get(index) != null) {
//				(hmap.get(index)).recipient_seq = seq;;
//			}
			
		}
	}
			

	//Get the private key of the sender
	public OneKey getSenderPrivateKey() {
		return sender_private_key;
	}
	
	//Get the public key of a recipient for a certain recipient ID
	public OneKey getRecipientPublicKey(byte[] recipient_id) {
		String index = Base64.encodeBytes(recipient_id);
		if(hmap.get(index) != null) {
			return hmap.get(index).recipient_public_key;
		} else {
			return null;
		}
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
	
	/**
	 * Adds a response sender key associated with a certain recipient to the map.
	 * Used for the optimized responses.
	 */
	public void addResponseSenderKey(byte[] recipientId, byte[] response_sender_key)
	{
		String index = Base64.encodeBytes(recipientId);	
		response_sender_keys.put(index, response_sender_key);
		
	}
	
	/**
	 * Get a response sender key associated with a certain recipient.
	 * Used for the optimized responses.
	 */
	public byte[] getResponseSenderKey(byte[] recipientId)
	{
		String index = Base64.encodeBytes(recipientId);	
		return response_sender_keys.get(index);
	}
	
	/**
	 * Check whether this context uses optimized responses or not.
	 * 
	 * @return true/false to indicate if optimized responses are used
	 */
	public boolean getOptimizedResponses() {
		return this.optimizedResponsesEnabled;
	}
	
	/**
	 * Sets whether this context uses optimized responses or not.
	 * 
	 * @param b true/false to indicate if optimized responses are used
	 */
	public void setOptimizedResponse(boolean b) {
		this.optimizedResponsesEnabled = b;
	}
	
	/**
	 * Generate a shared secret when using ECDSA.
	 * 
	 * @param sender_private_key the public/private key of the sender
	 * @param recipient_public_key the public key of the recipient
	 * @return the shared secret
	 */
	public byte[] generateSharedSecretECDSA(OneKey sender_private_key, OneKey recipient_public_key) {

		byte[] sharedSecret = null;
		try {
			ECPublicKey recipientPubKey = (ECPublicKey) recipient_public_key.AsPublicKey();
			ECPrivateKey senderPrivKey = (ECPrivateKey) sender_private_key.AsPrivateKey();
			
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(senderPrivKey);
			keyAgreement.doPhase(recipientPubKey, true);

			sharedSecret = keyAgreement.generateSecret();
		} catch (GeneralSecurityException | CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}
		
		return sharedSecret;
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
