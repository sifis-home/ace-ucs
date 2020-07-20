/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing Group OSCORE messages
 ******************************************************************************/
package org.eclipse.californium.groscore.group.interop;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.grcose.AlgorithmID;
import org.eclipse.californium.grcose.CoseException;
import org.eclipse.californium.grcose.KeyKeys;
import org.eclipse.californium.grcose.OneKey;
import org.eclipse.californium.groscore.HashMapCtxDB;
import org.eclipse.californium.groscore.OSCoreCtxDB;
import org.eclipse.californium.groscore.OSException;
import org.eclipse.californium.groscore.RequestDecryptor;
import org.eclipse.californium.groscore.RequestEncryptor;
import org.eclipse.californium.groscore.group.GroupCtx;
import org.eclipse.californium.groscore.group.GroupRecipientCtx;
import org.eclipse.californium.groscore.group.GroupSenderCtx;
import org.eclipse.californium.groscore.group.OneKeyDecoder;
import org.eclipse.californium.groscore.group.SharedSecretCalculation;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Tests key derivation for Group OSCORE for both ECDSA_256 and EdDSA
 * countersignature algorithms. The AEAD algorithm used is the default
 * AES-CCM-16-64-128 and the HKDF algorithm the default HKDF SHA-256.
 * 
 * 
 */
public class GroupInteropRikardEddsaTests {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	// OSCORE context information database
	private final static HashMapCtxDB db = new HashMapCtxDB();

	// Define AEAD and HKDF algorithms
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Imagined multicast addresses for recipient groups
	private static String groupEddsa = "coap://224.0.1.188";

	// Define context information (based on OSCORE RFC section C.3.2. Server)
	static byte[] sid = new byte[] { 0x0A };
	static byte[] rid1 = new byte[] { 0x51 };
	static byte[] rid2 = new byte[] { 0x52 };

	private final static byte[] master_secret = Utils.hexToBytes("11223344556677889900AABBCCDDEEFF");
	private final static byte[] master_salt = Utils.hexToBytes("1F2E3D4C5B6A7081");
	private final static byte[] context_id = Utils.hexToBytes("DD11");

	// Keys for sender and recipients
	// For the public keys only the public part will be added to the context
	private static String senderFullKeyEddsa = "{1: 1, 2: h'0A', -4: h'397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347', -2: h'CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159', -1: 6}";
	private static String recipient1PublicKeyEddsa = "{1: 1, 2: h'51', -4: h'70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A', -2: h'2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D', -1: 6}";
	private static String recipient2PublicKeyEddsa = "{1: 1, 2: h'52', -4: h'E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F', -2: h'5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF', -1: 6}";

	private static final int REPLAY_WINDOW = 32;

	// The contexts generated for use in the tests
	private static GroupSenderCtx senderCtxEddsa;

	private static GroupRecipientCtx recipient1CtxEddsa;
	private static GroupRecipientCtx recipient2CtxEddsa;

	/* --- Tests follow --- */

	@Test
	public void testEDDSAKeys() throws Exception {
		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		OneKey senderKey = OneKeyDecoder.parseDiagnostic(senderFullKeyEddsa);
		OneKey recipient1Key = OneKeyDecoder.parseDiagnostic(recipient1PublicKeyEddsa);
		OneKey recipient2Key = OneKeyDecoder.parseDiagnostic(recipient2PublicKeyEddsa);

		// Check the properties of the decoded keys

		// Key ID is set
		assertNotNull(senderKey.get(KeyKeys.KeyId));
		assertNotNull(recipient1Key.get(KeyKeys.KeyId));
		assertNotNull(recipient2Key.get(KeyKeys.KeyId));

		// Check that Key IDs are correct
		assertArrayEquals(sid, senderKey.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid1, recipient1Key.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid2, recipient2Key.get(KeyKeys.KeyId).GetByteString());

		// Key type
		assertEquals(KeyKeys.KeyType_OKP, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.OKP_Ed25519, senderKey.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient1Key.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient2Key.get(KeyKeys.OKP_Curve));

		// Attempt to sign using the keys to see that it works
		byte[] signatureBytes = OneKeyDecoderTest.doCountersign(senderKey);
		assertEquals(64, signatureBytes.length);
		signatureBytes = OneKeyDecoderTest.doCountersign(recipient1Key);
		assertEquals(64, signatureBytes.length);
		signatureBytes = OneKeyDecoderTest.doCountersign(recipient2Key);
		assertEquals(64, signatureBytes.length);
	}

	@Test
	public void testContextsAlgCountersign() throws OSException {
		// Check that the contexts use the correct countersignature algorithms

		assertEquals(AlgorithmID.EDDSA, senderCtxEddsa.getAlgCountersign());
		assertEquals(AlgorithmID.EDDSA, recipient1CtxEddsa.getAlgCountersign());
		assertEquals(AlgorithmID.EDDSA, recipient2CtxEddsa.getAlgCountersign());
	}

	@Test
	public void testSenderKeys() throws OSException {

		System.out.println("Sender key: " + Utils.bytesToHex(senderCtxEddsa.getSenderKey()));

		// Check that they match expected value
		byte[] expectedSenderKey = Utils.hexToBytes("33badb4d6b487e16bc8dc3f6db382990");
		assertArrayEquals(expectedSenderKey, senderCtxEddsa.getSenderKey());
	}

	@Test
	public void testRecipientKeys() throws OSException {

		System.out.println("Recipient 1 key: " + Utils.bytesToHex(recipient1CtxEddsa.getRecipientKey()));
		System.out.println("Recipient 2 key: " + Utils.bytesToHex(recipient2CtxEddsa.getRecipientKey()));

		// Check that they match expected value
		byte[] expectedRecipient1Key = Utils.hexToBytes("1809ba2d5dc543e600270023c29c31f8");
		assertArrayEquals(expectedRecipient1Key, recipient1CtxEddsa.getRecipientKey());

		byte[] expectedRecipient2Key = Utils.hexToBytes("3e55d62e4541dbf594dee14bc425d19b");
		assertArrayEquals(expectedRecipient2Key, recipient2CtxEddsa.getRecipientKey());

	}

	@Test
	public void testPairwiseRecipientKeys() throws OSException {

		byte[] recipient1EddsaPairwiseKey = recipient1CtxEddsa.getPairwiseRecipientKey();
		byte[] recipient2EddsaPairwiseKey = recipient2CtxEddsa.getPairwiseRecipientKey();

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(recipient1EddsaPairwiseKey, recipient2EddsaPairwiseKey));

		System.out.println("EdDSA: Recipient 1 Pairwise Key: " + Utils.bytesToHex(recipient1EddsaPairwiseKey));
		System.out.println("EdDSA: Recipient 2 Pairwise Key: " + Utils.bytesToHex(recipient2EddsaPairwiseKey));

		// Check that they match expected value

		assertArrayEquals(Utils.hexToBytes("2735818179dd21baa586482bf47fd4fb"), recipient1EddsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("41dbb059334de5a63f4fd67562f83561"), recipient2EddsaPairwiseKey);

	}

	@Test
	public void testPairwiseSenderKeys() throws OSException {
		byte[] senderEddsaPairwiseKey1 = senderCtxEddsa.getPairwiseSenderKey(rid1);
		byte[] senderEddsaPairwiseKey2 = senderCtxEddsa.getPairwiseSenderKey(rid2);

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(senderEddsaPairwiseKey1, senderEddsaPairwiseKey2));

		System.out.println("EdDSA: Sender Pairwise Key 1: " + Utils.bytesToHex(senderEddsaPairwiseKey1));
		System.out.println("EdDSA: Sender Pairwise Key 2: " + Utils.bytesToHex(senderEddsaPairwiseKey2));

		// Check that they match expected value

		assertArrayEquals(Utils.hexToBytes("bcc78daf03b2ce75c95b21ae7dee3a99"), senderEddsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("10fa30c43dbe436954084fcd90c1f6f2"), senderEddsaPairwiseKey2);

	}

	@Test
	public void testSharedSecretsEddsa() throws CoseException {
		// Check that recipient keys match in both contexts
		byte[] sharedSecret1 = SharedSecretCalculation.calculateSharedSecret(recipient1CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());
		byte[] sharedSecret2 = SharedSecretCalculation.calculateSharedSecret(recipient2CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());

		// Check that they do not match each other
		assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

		System.out.println("EdDSA: Shared secret 1 " + Utils.bytesToHex(sharedSecret1));
		System.out.println("EdDSA: Shared secret 2 " + Utils.bytesToHex(sharedSecret2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("bb11648af3dfebb35e612914a7a21fc751b001aceb0267c5536528e2b9261450"),
				sharedSecret2);
	}

	@Test
	public void testMessage3Reception() throws OSException {

		db.purge();

		int seq = 1;

		// --- Try decryption ---
		String destinationUri = "coap://127.0.0.1/test";

		GroupCtx groupCtxRikard = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.EDDSA);
		// Dummy values for pretend sender
		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(recipient2PublicKeyEddsa);
		groupCtxRikard.addSenderCtx(new byte[] { 0x11, 0x22 }, senderFullKey);

		groupCtxRikard.addRecipientCtx(sid, REPLAY_WINDOW, OneKeyDecoder.parseDiagnostic(senderFullKeyEddsa));
		db.addContext(destinationUri, groupCtxRikard);
		GroupRecipientCtx recipientCtx = (GroupRecipientCtx) db.getContext(sid,
				context_id);

		// Create request message from raw byte array
		String requestString = "58-02-FF-FF-11-84-AF-72-82-CE-23-BA-96-39-01-02-DD-11-0A-FF-42-41-71-AB-DF-18-40-50-29-79-42-02-2C-7A-85-E1-75-17-24-6B-31-DB-B1-0C-50-78-73-0E-9D-08-57-E3-EA-0A-63-0F-AF-D1-B2-24-23-64-7E-C0-9A-5D-60-C7-4F-1A-45-B2-95-DB-10-D5-56-9D-6D-A0-9F-44-3E-79-2D-6A-72-BF-BC-72-E3-2C-0D";
		requestString = requestString.replace("-", "");
		byte[] requestBytes = Utils.hexToBytes(requestString);

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		// Set up some state information simulating an incoming request
		OSCoreCtxDB db = new HashMapCtxDB();
		recipientCtx.setReceiverSeq(seq - 1);
		db.addContext(recipientCtx);
		r.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));

		System.out.println("Common IV: " + Utils.bytesToHex(recipientCtx.getCommonIV()));
		System.out.println("Recipient Key: " + Utils.bytesToHex(recipientCtx.getRecipientKey()));

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, r, recipientCtx);
		decrypted.getOptions().removeOscore();

		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted: " + Utils.bytesToHex(encryptedBytes));
	}

	@Test
	public void testMessage3Generation() throws OSException {
		senderCtxEddsa.setSenderSeq(1);

		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.setURI(groupEddsa);
		request.setToken(
				new byte[] { 0x11, (byte) 0x84, (byte) 0xAF, 0x72, (byte) 0x82, (byte) 0xCE, 0x23, (byte) 0xBA });
		
		
		// encrypt
		Request encrypted = RequestEncryptor.encrypt(db, request);

		System.out.println(encrypted);

		System.out.println("Common IV: " + hexPrintDash(senderCtxEddsa.getCommonIV()));
		System.out.println("Sender Key: " + hexPrintDash(senderCtxEddsa.getSenderKey()));

		System.out.println("Payload: " + hexPrintDash(encrypted.getPayload()));

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(encrypted);

		System.out.println("Full request: " + hexPrintDash(decryptedBytes));

	}

	private static String hexPrintDash(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X-", b));
		}
		return sb.toString();
	}

	/* --- End of tests --- */

	/**
	 * Derives OSCORE context information for tests
	 *
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	@BeforeClass
	public static void deriveContexts() throws OSException, CoseException {

		// Create context using EdDSA

		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		GroupCtx groupCtxEddsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.EDDSA);

		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(senderFullKeyEddsa);
		groupCtxEddsa.addSenderCtx(sid, senderFullKey);

		OneKey recipient1PublicKey = OneKeyDecoder.parseDiagnostic(recipient1PublicKeyEddsa).PublicKey();
		OneKey recipient2PublicKey = OneKeyDecoder.parseDiagnostic(recipient2PublicKeyEddsa).PublicKey();
		groupCtxEddsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEddsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEddsa, groupCtxEddsa);

		// Save the generated sender and recipient contexts

		senderCtxEddsa = (GroupSenderCtx) db.getContext(groupEddsa);
		recipient1CtxEddsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEddsa = (GroupRecipientCtx) db.getContext(rid2, context_id);

	}

}
