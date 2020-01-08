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
import java.util.Random;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.junit.Assert;

/**
 * 
 * Gathers generalized methods for encryption and compression of OSCORE
 * protected messages. Also encodes the OSCORE option.
 *
 */
public abstract class Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Encryptor.class.getName());

	/**
	 * Encrypt the COSE message using the OSCore context.
	 * 
	 * Rikard: Added recipientId
	 * 
	 * @param enc the encrypt structure
	 * @param ctx the OSCore context
	 * @param mess the message
	 *
	 * @return the COSE message
	 * 
	 * @throws OSException if encryption or encoding fails
	 */
	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message mess, boolean newPartialIV, byte[] recipientId)
			throws OSException {
		boolean isRequest = mess instanceof Request;
		//Boolean to indicate whether this is an optimized response
		boolean isOptimizedResponse = isRequest == false && ((GroupOSCoreCtx)ctx).getOptimizedResponses() == true;

		try {
			byte[] key = ctx.getSenderKey();
			byte[] partialIV = null;
			byte[] nonce = null;

			//If optimized responses are used and this is a response,
			//use the response sender key (for this recipient) instead
			if(ctx instanceof GroupOSCoreCtx && isOptimizedResponse) {
				key = ((GroupOSCoreCtx)ctx).getResponseSenderKey(recipientId);
			}
			
			//Rikard: Moved this here to always include the KID
			enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ctx.getSenderId()), Attribute.UNPROTECTED);
			
			if (isRequest) {
				partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), ctx.getCommonIV(),
						ctx.getIVLength());
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
			} else {
				
				//If recipient ID is null here and not using Group OSCORE simply take it from the OSCORE Context
				//When using Group OSCORE the Recipient ID should be provided in the call to this method
				if(recipientId == null) {
					//System.err.println("Error: Recipient ID was null!");
					if(ctx instanceof GroupOSCoreCtx == false) {
						recipientId = ctx.getRecipientId();
					}
				}

				if (!newPartialIV) {
					// use nonce from request
					
					int recSeq = -1;
					if(ctx instanceof GroupOSCoreCtx) {
						recSeq = ((GroupOSCoreCtx)ctx).getReceiverSeq(recipientId); 
						partialIV = OSSerializer.processPartialIV(recSeq);
					} else {
						partialIV = OSSerializer.processPartialIV(ctx.getReceiverSeq()); //Fixed
						//System.err.println("Should never happen for Group OSCORE!");
					}
					
					nonce = OSSerializer.nonceGeneration(partialIV, recipientId, ctx.getCommonIV(),
							ctx.getIVLength());
				} else {
					// response' creates its own partialIV
					partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
					nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), ctx.getCommonIV(),
							ctx.getIVLength());
				}
			}

			/* ------ Rikard: Prints for debugging ------ */

			boolean DETAILED_DEBUG = Utility.DETAILED_DEBUG;

			String messageType = "Response: ";
			if(isRequest) {
				messageType = "Request:  ";
			}

			if(DETAILED_DEBUG) {
				System.out.println("Encrypt " + messageType + "Common IV:\t" + Utility.arrayToString(ctx.getCommonIV()));
				System.out.println("Encrypt " + messageType + "Nonce:\t" + Utility.arrayToString(nonce));
				//System.out.println("Encrypt " + messageType + "Sequence Nr.:\t" + seq);
				System.out.println("Encrypt " + messageType + "Sender ID:\t" + Utility.arrayToString(ctx.getSenderId()));
				System.out.println("Encrypt " + messageType + "Sender Key:\t" + Utility.arrayToString(key));
				//System.out.println("Encrypt " + messageType + "Recipient ID:" + Utility.arrayToString(recipientId));
				System.out.println("Encrypt " + messageType + "Message KID:\t" + Utility.arrayToString(enc.findAttribute(HeaderKeys.KID).GetByteString()));
				//System.out.println("Encrypt " + messageType + "*Recipient Key:" + Utility.arrayToString(key));
				System.out.println("Encrypt " + messageType + "External AAD:\t" + Utility.arrayToString(enc.getExternal()));
				System.out.println("Encrypt " + messageType + "Optimized Response:\t" + isOptimizedResponse);
			}

			/* ------ End prints for debugging ------ */

			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);

			/* ------ Rikard: Add the countersignature (if using Group OSCORE) ------ */
			//TODO: Extract to separate method?
			//Skip signatures for responses when using the optimized responses
			if(ctx instanceof GroupOSCoreCtx && isOptimizedResponse == false) {
				OneKey sender_private_key = ((GroupOSCoreCtx)ctx).getSenderPrivateKey();
				CounterSign1 sign = new CounterSign1(sender_private_key);

				CBORObject sign_alg = ((GroupOSCoreCtx)ctx).getAlgCountersign().AsCBOR();
				sign.addAttribute(HeaderKeys.Algorithm, sign_alg, Attribute.DO_NOT_SEND);
				//sign.setExternal(enc.getExternal()); //Set external AAD taken from enc object
				
				enc.setCountersign1(sign);
				
				//Testing new external AAD for signing
				//byte[] currentExternalAAD = sign.getExternal();
				//System.out.println("Encrypting: Current external AAD:\t" + Utility.arrayToString(currentExternalAAD));
				byte[] newExternalAAD = null;
				if(mess instanceof Request) {
					newExternalAAD = OSSerializer.serializeSigningAAD(false, mess, ctx.getSenderId(), CoAP.VERSION, ctx.getSenderSeq(), ctx, mess.getOptions(), false);
				} else if (mess instanceof Response) {
					newExternalAAD = OSSerializer.serializeSigningAAD(false, mess, recipientId, CoAP.VERSION, ((GroupOSCoreCtx)ctx).getReceiverSeq(recipientId), ctx, mess.getOptions(), newPartialIV);
				}
				System.out.println("Encrypting: Signing external AAD:\t" + Utility.arrayToString(newExternalAAD));
				//Assert.assertArrayEquals(currentExternalAAD, newExternalAAD);
				//End testing new external AAD for signing
				
				sign.setExternal(newExternalAAD); //Set external AAD for signing
				
				enc.encrypt(key);

				CBORObject mySignature = enc.getUnprotectedAttributes().get(HeaderKeys.CounterSignature0.AsCBOR());
				byte[] countersign_bytes = mySignature.GetByteString();
				if(DETAILED_DEBUG) {
					System.out.println("Encrypt " + messageType + "Countersignature length:\t" + countersign_bytes.length);
					System.out.println("Encrypt " + messageType + "Countersignature bytes:\t" + Utility.arrayToString(countersign_bytes));

					byte[] keyObjectBytes = sender_private_key.AsCBOR().EncodeToBytes();
					String base64_encoded = Base64.getEncoder().encodeToString(keyObjectBytes);
					System.out.println("Encrypt " + messageType + "Sender Private Key:\t" + base64_encoded);
				}

				if(countersign_bytes.length != ((GroupOSCoreCtx)ctx).getCountersignLength()) {
					System.err.println("Error: Unexpected countersignature length!");
				}

				//If countersignature is not to be used empty the byte array
				if(((GroupOSCoreCtx)ctx).getCountersignLength() == 0) {
					countersign_bytes = new byte[0];
				}

				//Append countersignature to ciphertext
				byte[] ciphertext = enc.getEncryptedContent();

				if(DETAILED_DEBUG) {
					System.out.println("Encrypt: " + messageType + "Ciphertext bytes:\t" + Utility.arrayToString(ciphertext));
				}
				
				ByteArrayOutputStream os = new ByteArrayOutputStream( );
				try {
					os.write(ciphertext);
					os.write(countersign_bytes);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				byte[] full_payload = os.toByteArray();

				/* ------ End add the countersignature	------ */

				return full_payload;
			} else { //If using normal OSCORE, or optimized responses
				enc.encrypt(key);
				return enc.getEncryptedContent();
			}
		} catch (CoseException e) {
			LOGGER.error("COSE/Crypto exception: " + e.getMessage());
			e.printStackTrace();
			throw new OSException(e.getMessage());
		}
	}

	//Rikard: Old method that did not support supplying recipientId
	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message mess, boolean newPartialIV)
			throws OSException {
		return encryptAndEncode(enc, ctx, mess, newPartialIV, null);
	}

	/**
	 * Serialize the Additional Authenticated Data (AAD).
	 * 
	 * @param m the message
	 * @param ctx the OSCore context
	 * @return the serialized AAD
	 */
	protected static byte[] serializeAAD(Message m, OSCoreCtx ctx, final boolean newPartialIV, byte[] recipientId) {
		if (m instanceof Request) {
			Request r = (Request) m;
			return OSSerializer.serializeSendRequestAAD(CoAP.VERSION, ctx, r.getOptions());
		} else if (m instanceof Response) {
			Response r = (Response) m;
			return OSSerializer.serializeSendResponseAAD(CoAP.VERSION, ctx, r.getOptions(), newPartialIV, recipientId);
		}
		return null;
	}
	
	//Rikard: Split methods to be able to provide recipient ID in call
	protected static byte[] serializeAAD(Message m, OSCoreCtx ctx, final boolean newPartialIV) {
		return serializeAAD(m, ctx, newPartialIV, null);
	}

	/**
	 * Initiates the encrypt0message object and sets the confidential (plaintext
	 * to be encrypted) and the aad.
	 * 
	 * @param confidential the plaintext to be encrypted
	 * @param aad the aad
	 * @return the intiated and prepared encrypt0message object
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] confidential, byte[] aad) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		enc.SetContent(confidential);
		enc.setExternal(aad);
		return enc;
	}

	/**
	 * Compresses the message by encoding the Object-Security value and sets the
	 * message's payload to the cipherText.
	 * 
	 * @param ctx the OSCoreCtx
	 * @param cipherText the cipher text to be appended to this compression
	 * @param message the message
	 * @return the entire message's byte array
	 */
	protected static byte[] compression(OSCoreCtx ctx, byte[] cipherText, Message message, final boolean newPartialIV) {
		boolean request = message instanceof Request;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		OptionSet options = message.getOptions();
		options.removeOscore();

		if (request) {
			message.getOptions().setOscore(encodeOSCoreRequest(ctx));
		} else {
			message.getOptions().setOscore(encodeOSCoreResponse(ctx, newPartialIV));
		}

		if (cipherText != null) {
			message.setPayload(cipherText);
		}

		return bRes.toByteArray();
	}

	/**
	 * Encodes the Object-Security value for a Request.
	 * 
	 * @param ctx the context
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreRequest(OSCoreCtx ctx) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		byte[] partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
		firstByte = firstByte | (partialIV.length & 0x07); //PartialIV length
		firstByte = firstByte | 0x08; //Set the KID bit
		
		//Rikard: If the Context ID bit is present in the context set its bit
		if(ctx.getIdContext() != null) {
			firstByte = firstByte | 0x10;
		}
		
		bRes.write(firstByte);
		
		try {
			bRes.write(partialIV);
			
			//Rikard: Encode the Context ID value if present in the context
			//TODO: Comment this method better here and in the OSCORE code
			//TODO: Use terms from OSCORE draft section 6.1
			if(ctx.getIdContext() != null) {
				bRes.write(ctx.getIdContext().length); //Context ID length
				bRes.write(ctx.getIdContext()); //Context ID value;
			}
			
			bRes.write(ctx.getSenderId());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bRes.toByteArray();
	}

	/**
	 * Encodes the Object-Security value for a Response.
	 * 
	 * @param ctx the context
	 * @param newPartialIV if true encodes the partialIV, otherwise partialIV is
	 *            not encoded
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreResponse(OSCoreCtx ctx, final boolean newPartialIV) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		
		//Include KID in response if using Group OSCORE
		if(ctx instanceof GroupOSCoreCtx) {
			firstByte = firstByte | 0x08; //Rikard: Set the KID bit
		}
		
		byte[] partialIV = null;
		if (newPartialIV) {
			partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
			firstByte = firstByte | (partialIV.length & 0x07);
		}
		
		try {
			bRes.write(firstByte);
			if(newPartialIV) {
				bRes.write(partialIV);
			}
			//Include KID in response if using Group OSCORE
			if(ctx instanceof GroupOSCoreCtx) {
				bRes.write(ctx.getSenderId()); //Rikard: Write sender ID
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	
		return bRes.toByteArray();
	}
}
