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

import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.oscore.group.GroupOSCoreCtx;
import org.eclipse.californium.oscore.group.Utility;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * Implements methods for serializing OSCORE data, creating AAD, reading data
 * and generating nonce.
 *
 */
public class OSSerializer {

	private static final byte[] ONE_ZERO = new byte[] { 0x00 };
	private static final byte[] EMPTY = new byte[0];

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSSerializer.class.getName());

	/**
	 * Prepare options and payload for encrypting.
	 * 
	 * @param options the options
	 * 
	 * @param payload the payload
	 * 
	 * @return the serialized plaintext for OSCore
	 */
	public static byte[] serializeConfidentialData(OptionSet options, byte[] payload, int realCode) {
		if (options != null) {
			DatagramWriter writer = new DatagramWriter();
			if (realCode > 0) {
				OptionSet filteredOptions = OptionJuggle.prepareEoptions(options);
				writer.write(realCode, CoAP.MessageFormat.CODE_BITS);
				DataSerializer.serializeOptionsAndPayload(writer, filteredOptions, payload);
				return writer.toByteArray();
			} else {
				LOGGER.error(ErrorDescriptions.COAP_CODE_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.COAP_CODE_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
			throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
		}
	}
	
	/**
	 * Rikard: Adds the new parameters alg_countersign & par_countersign
	 * to the algorithms array in the external AAD for Group OSCORE Contexts.
	 * 
	 * @param ctx
	 * @param algorithms
	 */
	private static void addGroupOSCoreAlgs(OSCoreCtx ctx, CBORObject algorithms) {
		if(ctx instanceof GroupOSCoreCtx) {
			algorithms.Add(((GroupOSCoreCtx)ctx).getAlgCountersign().AsCBOR());

			if(((GroupOSCoreCtx)ctx).getParCountersign() != null) {
				CBORObject parCountersignCBOR = CBORObject.FromObject(((GroupOSCoreCtx)ctx).getParCountersign());
				algorithms.Add(parCountersignCBOR);
				
				//TODO: Extract to context.
				CBORObject cs_key_params = CBORObject.NewArray();
				if(((GroupOSCoreCtx)ctx).getAlgCountersign() == AlgorithmID.EDDSA) { //When using EDDSA.
					cs_key_params.Add(CBORObject.FromObject((int)1)); 
					cs_key_params.Add(CBORObject.FromObject((int)6)); //When using ECDSA_256
				} else if(((GroupOSCoreCtx)ctx).getAlgCountersign() == AlgorithmID.ECDSA_256) {
					cs_key_params.Add(CBORObject.FromObject((int)26));
					cs_key_params.Add(CBORObject.FromObject((int)1));
				}

				algorithms.Add(CBORObject.FromObject(cs_key_params));
			}
		}
	}

	/**
	 * Prepare the additional authenticated data of a response to be sent.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param ctx the OSCore context
	 * @param options the option set
	 * 
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeSendResponseAAD(int version, OSCoreCtx ctx, OptionSet options, boolean newPartialIV, byte[] recipientId) {
		if (version == CoAP.VERSION) {
			if (ctx != null) {
				if (options != null) {
					CBORObject algorithms = CBORObject.NewArray();
					algorithms.Add(ctx.getAlg().AsCBOR());
					
					//Rikard: If this is a Group OSCORE Context add AAD material 
					addGroupOSCoreAlgs(ctx, algorithms);

					CBORObject aad = CBORObject.NewArray();
					aad.Add(version);
					aad.Add(algorithms);
					
					if(recipientId != null) {
						aad.Add(recipientId); //Rikard: Added this
					} else {
						//System.err.println("This should never happen for Group OSCORE!");
						aad.Add(ctx.getRecipientId()); //Fixed
					}

					if (newPartialIV) {
						aad.Add(processPartialIV(ctx.getSenderSeq()));
					} else { //Rikard: Make sure to get recipient seq. for particular recipient ID 
						
						if(ctx instanceof GroupOSCoreCtx) {
							aad.Add(processPartialIV(((GroupOSCoreCtx)ctx).getReceiverSeq(recipientId)));
						} else {
							aad.Add(processPartialIV(ctx.getReceiverSeq())); //Fixed
							//System.err.println("Should not happen for Group OSCORE!");
						}
						
					}
					
					//Added the last parameter which should be the options
					aad.Add(CBORObject.FromObject(EMPTY));

					return aad.EncodeToBytes();
				} else {
					LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
					throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.CTX_NULL);
				throw new NullPointerException(ErrorDescriptions.CTX_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}
	
	//Rikard: New method
	public static byte[] serializeSendResponseAAD(int version, OSCoreCtx ctx, OptionSet options, boolean newPartialIV) {
		return serializeSendResponseAAD(version, ctx, options, newPartialIV, null);
	}

//	/**
//	 * Prepare the additional authenticated data of a message.
//	 * 
//	 * Note that for the request* parameters they must contain the value of what was in
//	 * a request. Either this actual request or the request associated to this response. 
//	 * 
//	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_piv :
//	 * bstr, options : bstr]
//	 * 
//	 * @param version the CoAP version number
//	 * @param algorithm AEAD algorithm
//	 * @param requestSeq the sequence number (request PIV)
//	 * @param requestSenderId sender ID (request KID)
//	 * @param options the option set
//	 * @return byte array with AAD
//	 */
//	public static byte[] serializeAAD(int version, AlgorithmID algorithm, int requestSeq, byte[] requestSenderId, OptionSet options) {
//		if (version == CoAP.VERSION) {
//			if (requestSeq > -1) {
//				if (algorithm != null) {
//					if (options != null) {
//						CBORObject algorithms = CBORObject.NewArray();
//						algorithms.Add(algorithm.AsCBOR());
//
//						CBORObject aad = CBORObject.NewArray();
//						aad.Add(version);
//						aad.Add(algorithms);
//						aad.Add(requestSenderId);
//						aad.Add(processPartialIV(requestSeq));
//						
//						//I-class options (currently none)
//						aad.Add(CBORObject.FromObject(EMPTY));
//						
//						return aad.EncodeToBytes();
//					} else {
//						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
//						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
//					}
//				} else {
//					LOGGER.error(ErrorDescriptions.ALGORITHM_NOT_DEFINED);
//					throw new NullPointerException(ErrorDescriptions.ALGORITHM_NOT_DEFINED);
//				}
//			} else {
//				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
//				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
//			}
//		} else {
//			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
//			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
//		}
//	}

	
	/**
	 * Prepare the additional authenticated data of a message for signing.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param seq the sequence number
	 * @param ctx the OSCore context
	 * @param options the option set
	 * 
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeSigningAAD(boolean incoming, Message message, byte[] senderID, int version, int seq, OSCoreCtx ctx, OptionSet options, boolean newPartialIV) {
		if (version == CoAP.VERSION) { //FIXME, OSCORE version
			if (seq > -1) {
				if (ctx != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(ctx.getAlg().AsCBOR());

						//Rikard: If this is a Group OSCORE Context add AAD material 
						addGroupOSCoreAlgs(ctx, algorithms);
						
						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);
						
						aad.Add(senderID);
						aad.Add(processPartialIV(seq));

						//Added the last parameter which should be the options
						aad.Add(CBORObject.FromObject(EMPTY));
						
						//Add the OSCORE option (external AAD for signature)
						byte[] optionBytes = null;
						if(!incoming) {
							if(message instanceof Request) {
								optionBytes = Encryptor.encodeOSCoreRequest(ctx);
							} else {
								optionBytes = Encryptor.encodeOSCoreResponse(ctx, newPartialIV);
							}
						} else {
							optionBytes = message.getOptions().getOscore();
						}
						aad.Add(CBORObject.FromObject(optionBytes)); //Add OSCORE option value
						
						System.out.println(("OSCORE Option value: " + Utility.arrayToString(optionBytes)));
						
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new NullPointerException(ErrorDescriptions.CTX_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Prepare the additional authenticated data of a received response.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param seq the sequence number
	 * @param ctx the OSCore context
	 * @param options the option set
	 * 
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeReceiveResponseAAD(int version, int seq, OSCoreCtx ctx, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (seq > -1) {
				if (ctx != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(ctx.getAlg().AsCBOR());

						//Rikard: If this is a Group OSCORE Context add AAD material 
						addGroupOSCoreAlgs(ctx, algorithms);
						
						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);
						aad.Add(ctx.getSenderId());
						aad.Add(processPartialIV(seq));
						
						//Added the last parameter which should be the options
						aad.Add(CBORObject.FromObject(EMPTY));
						
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new NullPointerException(ErrorDescriptions.CTX_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}
	
	/**
	 * Prepare the additional authenticated data of a request to be sent.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param ctx the OSCore context@param code
	 * @param options the option set
	 * 
	 *
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeSendRequestAAD(int version, OSCoreCtx ctx, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (ctx != null) {
				if (options != null) {
					CBORObject algorithms = CBORObject.NewArray();
					algorithms.Add(ctx.getAlg().AsCBOR());
					
					//Rikard: If this is a Group OSCORE Context add AAD material 
					addGroupOSCoreAlgs(ctx, algorithms);

					CBORObject aad = CBORObject.NewArray();
					aad.Add(version);
					aad.Add(algorithms);
					aad.Add(ctx.getSenderId());
					aad.Add(processPartialIV(ctx.getSenderSeq()));
					
					//Added the last parameter which should be the options
					aad.Add(CBORObject.FromObject(EMPTY));
					
					return aad.EncodeToBytes();
				} else {
					LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
					throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.CTX_NULL);
				throw new NullPointerException(ErrorDescriptions.CTX_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Prepare the additional authenticated data of a received request.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param seq the sent sequence number
	 * @param ctx the OSCore context@param code
	 * @param options the option set
	 * 
	 *
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeReceiveRequestAAD(int version, int seq, OSCoreCtx ctx, OptionSet options, byte[] recipientId) {
		if (version == CoAP.VERSION) {
			if (seq > -1) {
				if (ctx != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(ctx.getAlg().AsCBOR());
						
						//Rikard: If this is a Group OSCORE Context add AAD material 
						addGroupOSCoreAlgs(ctx, algorithms);

						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);

						if(recipientId != null) {
							aad.Add(recipientId); //Rikard: Added this
						} else {
							//System.err.println("This should never happen for Group OSCORE!");
							aad.Add(ctx.getRecipientId()); //Fixed
						}
						
						aad.Add(processPartialIV(seq));
						
						//Added the last parameter which should be the options
						aad.Add(CBORObject.FromObject(EMPTY));
						
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new NullPointerException(ErrorDescriptions.CTX_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}
	
	//Rikard: New method
	public static byte[] serializeReceiveRequestAAD(int version, int seq, OSCoreCtx ctx, OptionSet options) {
		return serializeReceiveRequestAAD(version, seq, ctx, options, null);
	}

	/**
	 * Generates the nonce.
	 * See https://core-wg.github.io/oscoap/draft-ietf-core-object-security.html#nonce
	 * 
	 * @param partialIV
	 * @param senderID
	 * @param commonIV
	 * @param nonceLength the algorithm dependent length of nonce
	 * @return the generated nonce or null if either one of the input parameters
	 *         are null
	 * @throws OSException if any of the parameters are unvalid
	 */
	public static byte[] nonceGeneration(byte[] partialIV, byte[] senderID, byte[] commonIV, int nonceLength)
			throws OSException {
		if (partialIV != null) {
			if (senderID != null) {
				if (commonIV != null) {
					if (nonceLength > 0) {
						int s = senderID.length;
						int zeroes = 5 - partialIV.length;

						if (zeroes > 0) {
							partialIV = leftPaddingZeroes(partialIV, zeroes);
						}

						zeroes = (nonceLength - 6) - senderID.length;

						if (zeroes > 0) {
							senderID = leftPaddingZeroes(senderID, zeroes);
						}

						zeroes = nonceLength - commonIV.length;

						if (zeroes > 0) {
							commonIV = leftPaddingZeroes(commonIV, zeroes);
						}

						byte[] tmp = new byte[1 + senderID.length + partialIV.length];
						tmp[0] = (byte) s;
						System.arraycopy(senderID, 0, tmp, 1, senderID.length);
						System.arraycopy(partialIV, 0, tmp, senderID.length + 1, partialIV.length);

						byte[] result = new byte[commonIV.length];

						int i = 0;
						for (byte b : tmp) {
							result[i] = (byte) (b ^ commonIV[i++]);
						}

						return result;
					} else {
						LOGGER.error(ErrorDescriptions.NONCE_LENGTH_INVALID);
						throw new IllegalArgumentException(ErrorDescriptions.NONCE_LENGTH_INVALID);
					}
				} else {
					LOGGER.error(ErrorDescriptions.COMMON_IV_NULL);
					throw new NullPointerException(ErrorDescriptions.COMMON_IV_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SENDER_ID_NULL);
				throw new NullPointerException(ErrorDescriptions.SENDER_ID_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.PARTIAL_IV_NULL);
			throw new NullPointerException(ErrorDescriptions.PARTIAL_IV_NULL);
		}
	}

	/**
	 * Padds the left side of the byte array paddMe with zeros as the int zeros
	 * has
	 * 
	 * @param paddMe
	 * @param zeros
	 * @return the left-padded byte array
	 */
	public static byte[] leftPaddingZeroes(byte[] paddMe, int zeros) {
		byte[] tmp = new byte[zeros + paddMe.length];
		System.arraycopy(paddMe, 0, tmp, zeros, paddMe.length);
		return tmp;
	}

	/**
	 * Processes a partialIV correctly
	 * 
	 * @param value the partialIV
	 * @return the processed partialIV
	 */
	public static byte[] processPartialIV(int value) {
		byte[] partialIV = ByteBuffer.allocate(Decryptor.INTEGER_BYTES).putInt(value).array();
		return stripZeroes(partialIV);
	}

	/**
	 * Remove trailing zeroes in a byte array
	 * 
	 * @param in the incoming array
	 * @return the array with trailing zeroes removed
	 */
	public static byte[] stripZeroes(byte[] in) {
		if (in != null) {
			if (in.length == 0) {
				return EMPTY;
			}
			if (in.length == 1)
				return in;

			int firstValue = 0;

			while (firstValue < in.length && in[firstValue] == 0) {
				firstValue++;
			}

			int newLength = in.length - firstValue;

			if (newLength == 0) {
				return ONE_ZERO;
			}

			byte[] out = new byte[newLength];
			System.arraycopy(in, firstValue, out, 0, out.length);

			return out;
		} else {
			LOGGER.error(ErrorDescriptions.BYTE_ARRAY_NULL);
			throw new NullPointerException(ErrorDescriptions.BYTE_ARRAY_NULL);
		}
	}
}
