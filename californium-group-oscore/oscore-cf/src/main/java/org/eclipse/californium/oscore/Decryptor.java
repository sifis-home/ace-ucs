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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;

/**
 * 
 * Gathers generalized methods for decryption and decompression of OSCORE
 * protected messages. Also provides decoding of the encoded OSCORE option
 *
 */
public abstract class Decryptor {
	/**
	 * Java 1.6 compatibility.
	 */
	public static final int INTEGER_BYTES = Integer.SIZE / Byte.SIZE;

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Decryptor.class.getName());

	protected static final OptionSet EMPTY = new OptionSet();

	/**
	 * Decrypts and decodes the message.
	 * 
	 * @param enc the COSE structure
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param seqByToken the sequence number
	 * 
	 * @return the decrypted plaintext
	 *
	 * @throws OSException if decryption or decoding fails
	 */
	protected static byte[] decryptAndDecode(Encrypt0Message enc, Message message, OSCoreCtx ctx, Integer seqByToken)
			throws OSException, CoseException {
		int seq = -2;
		boolean isRequest = message instanceof Request;
		byte[] nonce = null;
		byte[] partialIV = null;
		byte[] recipientId = null;
		
		if (isRequest) {

			CBORObject tmp = enc.findAttribute(HeaderKeys.PARTIAL_IV);
			
			//Rikard: Take recipient ID from message instead of context
			recipientId = enc.findAttribute(HeaderKeys.KID).GetByteString();

			if (tmp == null) {
				LOGGER.error("Decryption failed: no partialIV in request");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			} else {

				partialIV = tmp.GetByteString();
				partialIV = expandToIntSize(partialIV);
				seq = ByteBuffer.wrap(partialIV).getInt();
				
				//Note that the code below can throw an OSException when replays are detected
				if(ctx instanceof GroupOSCoreCtx) {
					//ctx.checkIncomingSeq(seq); //Fixed
					((GroupOSCoreCtx)ctx).checkIncomingSeq(seq, recipientId);
				}
				else {
					ctx.checkIncomingSeq(seq); //Fixed
				}

				nonce = OSSerializer.nonceGeneration(partialIV, recipientId, ctx.getCommonIV(),
						ctx.getIVLength());
			}
		} else { //Response
			if (seqByToken == null) {
				LOGGER.error("Decryption failed: the arrived response is not connected to a request we sent");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			}

			CBORObject tmp = enc.findAttribute(HeaderKeys.PARTIAL_IV);

			//Rikard: Use sequence number from original request for AAD calculation
			seq = seqByToken;

			if (tmp == null) {

				//Rikard: Take recipient ID from message instead of context if using Group OSCORE
				//For Group OSCORE it is always there in responses, but not for OSCORE.
				if(ctx instanceof GroupOSCoreCtx) {
					recipientId = enc.findAttribute(HeaderKeys.KID).GetByteString();
				} else { //Otherwise take it from the OSCORE Context
					recipientId = ctx.getRecipientId();
				}
				
				// this should use the partialIV that arrived in the request and
				// not the response
				//seq = seqByToken;
				partialIV = ByteBuffer.allocate(INTEGER_BYTES).putInt(seqByToken).array();
				nonce = OSSerializer.nonceGeneration(partialIV,	ctx.getSenderId(), ctx.getCommonIV(), 
						ctx.getIVLength());
			} else {

				//Rikard: Take recipient ID from message instead of context (for Group OSCORE)
				if(ctx instanceof GroupOSCoreCtx) {
					recipientId = enc.findAttribute(HeaderKeys.KID).GetByteString();
				} else {
					//For OSCORE the recipientID can be taken from the OSCORE Context
					//since the response will not contain a KID.
					recipientId = ctx.getRecipientId();
				}

				partialIV = tmp.GetByteString();
				partialIV = expandToIntSize(partialIV);
				//seq = ByteBuffer.wrap(partialIV).getInt();
				nonce = OSSerializer.nonceGeneration(partialIV, recipientId, ctx.getCommonIV(),
						ctx.getIVLength());
			}
		}

		byte[] plaintext = null;
		//Rikard: Use special method if this is Group OSCORE Context
		byte[] key;
		if(ctx instanceof GroupOSCoreCtx) {
			//System.out.println("Recipient ID:" + recipientId[0]);
			key = ((GroupOSCoreCtx)ctx).getRecipientKey(recipientId);
		} else {
			key = ctx.getRecipientKey(); //Fixed
		}
		byte[] aad = serializeAAD(message, ctx, seq, recipientId);

		enc.setExternal(aad);
		
		/* ------ Rikard: Prepare check of the countersignature	------ */
		//TODO: Move to different method?
		//Rikard: TODO: Clean up, Fail if sig is bad
		CounterSign1 sign = null;
		if(ctx instanceof GroupOSCoreCtx) {

			//First remove the countersignature from the payload (if existing and if using Group OSCORE)
			byte[] full_payload = null;
			try {
				full_payload = enc.getEncryptedContent();
			} catch (CoseException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			int countersignature_length = ((GroupOSCoreCtx)ctx).getCountersignLength();
			byte[] countersign_bytes  = Arrays.copyOfRange(full_payload, full_payload.length - countersignature_length, full_payload.length);

			if(Utility.DETAILED_DEBUG) {
				System.out.println("Decrypt " + "Countersignature length:\t" + countersign_bytes.length);
				System.out.println("Decrypt " + "Countersignature bytes:\t" + Utility.arrayToString(countersign_bytes));
			}

			byte[] ciphertext = Arrays.copyOfRange(full_payload, 0, full_payload.length - countersignature_length);

			enc.setEncryptedContent(ciphertext); //Rikard: Set new truncated ciphertext

			//Now actually prepare to check the countersignature
			OneKey recipient_public_key = ((GroupOSCoreCtx)ctx).getRecipientPublicKey(recipientId);
			//countersign_bytes[3] = (byte) 0xff; //Corrupt countersignature
			sign = new CounterSign1(countersign_bytes);
			sign.setKey(recipient_public_key);

			if(Utility.DETAILED_DEBUG) {
				byte[] keyObjectBytes = recipient_public_key.AsCBOR().EncodeToBytes();
				String base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);
				System.out.println("Decrypt " + "Recipient Public Key:\t" + base64_encoded);
			}

			CBORObject sign_alg = ((GroupOSCoreCtx)ctx).getAlgCountersign().AsCBOR();
			sign.addAttribute(HeaderKeys.Algorithm, sign_alg, Attribute.DO_NOT_SEND);

			sign.setExternal(enc.getExternal()); //Set external AAD taken from enc object

			//CBORObject countersign_cbor = CBORObject.FromObject(countersign_bytes);
			//enc.addAttribute(HeaderKeys.CounterSignature0.AsCBOR(), countersign_cbor, Attribute.UNPROTECTED);
			//sign.addAttribute(HeaderKeys.CounterSignature0.AsCBOR(), countersign_cbor, Attribute.UNPROTECTED);

			//boolean valid = false;
			//valid = enc.validate(sign);
			//System.out.println("Decrypt " + "Countersignature Valid:\t" + valid);

		}

		/* ------ End prepare check of the countersignature	------ */


		/* ------ Rikard: Prints for debugging ------ */

		boolean DEBUG = Utility.DETAILED_DEBUG;

		String messageType = "Response: ";
		if(isRequest) {
			messageType = "Request:  ";
		}

		if(DEBUG) {
			//System.out.println("Decrypt " + messageType + "Common IV:\t" + Utility.arrayToString(ctx.getCommonIV()));
			System.out.println("Decrypt " + messageType + "Nonce:\t" + Utility.arrayToString(nonce));
			//System.out.println("Decrypt " + messageType + "Sequence Nr.:\t" + seq);
			//System.out.println("Decrypt " + messageType + "Sender ID:\t" + Utility.arrayToString(ctx.getSenderId()));
			//System.out.println("Decrypt " + messageType + "Sender Key:\t" + Utility.arrayToString(ctx.getSenderKey()));
			//System.out.println("Decrypt " + messageType + "Recipient ID:" + Utility.arrayToString(recipientId));
			if(ctx instanceof GroupOSCoreCtx) { //If using Group OSCORE take the KID from the response
				System.out.println("Decrypt " + messageType + "Message KID:\t" + Utility.arrayToString(enc.findAttribute(HeaderKeys.KID).GetByteString()));
			} else { //For OSCORE take the KID from the OSCORE Context
				System.out.println("Decrypt " + messageType + "Message KID:\t" + Utility.arrayToString(ctx.getRecipientId()));
			}

			System.out.println("Decrypt " + messageType + "Recipient Key:" + Utility.arrayToString(key));
			System.out.println("Decrypt " + messageType + "External AAD:\t" + Utility.arrayToString(aad));
		}

		/* ------ End prints for debugging ------ */

		try {

			enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg().AsCBOR(), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			plaintext = enc.decrypt(key);

			//Rikard: Now finally check the countersignature (seems it must be done after decryption)
			if(ctx instanceof GroupOSCoreCtx) {
				boolean countersign_valid = false;
				countersign_valid = enc.validate(sign);

				if(countersign_valid == false) {
					System.err.println("Error: Countersignature verification failed!");
				}

				if(DEBUG) {
					System.out.println("Decrypt " + messageType + "Countersignature Valid:\t" + countersign_valid);
				}
			}

		} catch (CoseException e) {
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED + " " + e.getMessage());
			throw new OSException(ErrorDescriptions.DECRYPTION_FAILED + " " + e.getMessage());
		}

		return plaintext;
	}

	private static byte[] expandToIntSize(byte[] partialIV) throws OSException {
		if (partialIV.length > INTEGER_BYTES) {
			LOGGER.error("The partial IV is: " + partialIV.length + " long, " + INTEGER_BYTES + " was expected");
			throw new OSException("Partial IV too long");
		} else if (partialIV.length == INTEGER_BYTES) {
			return partialIV;
		}
		byte[] ret = new byte[INTEGER_BYTES];
		for (int i = 0; i < partialIV.length; i++) {
			ret[INTEGER_BYTES - partialIV.length + i] = partialIV[i];
		}
		return ret;

	}

	/**
	 * @param protectedData the protected data to decrypt
	 * @return the COSE structure
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] protectedData) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		try {
			enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(protectedData));
		} catch (CoseException e) {
			e.printStackTrace();
		}
		return enc;
	}

	/**
	 * Prepare the AAD.
	 * Rikard: Special version taking a separate recipient ID.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param seq the sequence number
	 * 
	 * @return the serialized AAD
	 */
	protected static byte[] serializeAAD(Message message, OSCoreCtx ctx, int seq, byte[] recipientId) {
		if (message instanceof Request) {
			Request r = (Request) message;
			return OSSerializer.serializeReceiveRequestAAD(CoAP.VERSION, seq, ctx, r.getOptions(), recipientId);
		} else if (message instanceof Response) {
			Response r = (Response) message;
			return OSSerializer.serializeReceiveResponseAAD(CoAP.VERSION, seq, ctx, r.getOptions());
		}
		return null;
	}
	
	//Rikard: Split methods
	protected static byte[] serializeAAD(Message message, OSCoreCtx ctx, int seq) {
		return serializeAAD(message, ctx, seq, null);
	}

	/**
	 * Decompress the message.
	 * 
	 * @param cipherText the encrypted data
	 * @param message the received message
	 * @return the Encrypt0Message
	 * @throws OSException
	 */
	protected static Encrypt0Message decompression(byte[] cipherText, Message message) throws OSException {
		Encrypt0Message enc = new Encrypt0Message(false, true);

		//Added try-catch for general Exception. The array manipulation can cause exceptions.
		try {
			decodeObjectSecurity(message, enc);
		} catch (OSException e) {
			LOGGER.error(e.getMessage());
			throw e;
		} catch (Exception e) {
			LOGGER.error("Failed to decode object security option.");
			throw new OSException("Failed to decode object security option.");
		}

		if (cipherText != null)
			enc.setEncryptedContent(cipherText);
		return enc;
	}

	/**
	 * Decodes the Object-Security value.
	 * 
	 * @param message the received message
	 * @param enc the Encrypt0Message object
	 * @throws OSException
	 */
	private static void decodeObjectSecurity(Message message, Encrypt0Message enc) throws OSException {
		byte[] total = message.getOptions().getOscore();

		/**
		 * If the OSCORE option value is a zero length byte array
		 * it represents a byte array of length 1 with a byte 0x00
		 * See https://tools.ietf.org/html/draft-ietf-core-object-security-15#page-33 point 4  
		 */
		if(total.length == 0) {
			total = new byte[] { 0x00 };
		}
		
		byte flagByte = total[0];

		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0x10; //Rikard: Changed this value

		byte[] partialIV = null;
		byte[] kid = null;
		int index = 1;

		if (n > 0) {
			try {
				partialIV = Arrays.copyOfRange(total, index, index + n);
				index += n;
			} catch (Exception e) {
				LOGGER.error("Partial_IV is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		if (h == 16) {
			int s = total[index];
			
			byte[] contextID = Arrays.copyOfRange(total, index + 1, index + 1 + s); //Rikard: Added this

			index += s + 1; //Rikard: Changed this to skip s bytes + 1 byte for s itself
			
			//Rikard: Added print below
			System.out.print("Received KID Context: 0x");
			for(int i = 0 ; i < contextID.length ; i++) {
				System.out.print(String.format("%02X", contextID[i]));
			}
			System.out.println("");
			
			if (s > 0) {
				//Rikard:
				//LOGGER.error("Kidcontext is included, but it is not supported. We ignore it and continue processing.");
			} else {
				LOGGER.error("Kid context is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		if (k == 8) {
			kid = Arrays.copyOfRange(total, index, total.length);
		} else {
			if (message instanceof Request) {
				LOGGER.error("Kid is missing from message when it is expected.");
				throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
			}
		}

		try {
			if (partialIV != null) {
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
			}
			if (kid != null) {
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(kid), Attribute.UNPROTECTED);
			}
		} catch (CoseException e) {
			LOGGER.error("COSE processing of message failed.");
			e.printStackTrace();
		}
	}

	/**
	 * Replaces the message's options with a new OptionSet which doesn't contain
	 * any of the non-special E options as outer options
	 * 
	 * @param message
	 */
	protected static void discardEOptions(Message message) {
		OptionSet newOptions = OptionJuggle.discardEOptions(message.getOptions());
		message.setOptions(newOptions);
	}
}
