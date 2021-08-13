package se.sics.ace;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;

import COSE.KeyKeys;

public class Util {

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
     * N.B. If the input array is 4 bytes in size, the returned integer may be negative!
     *      The calling method has to check, if relevant!
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
	
    /**
     * Build the "psk_identity" to use in the
     * ClientKeyExchange DTLS Handshake message
     *  
     * @param kid   The 'kid' of the key used as PoP key
     * 
     * @return The "psk_identity" to use in the DTLS Handshake
     */
	public static byte[] buildDtlsPskIdentity(byte[] kid) {
        
        CBORObject identityMap = CBORObject.NewMap();
        CBORObject cnfMap = CBORObject.NewMap();
        CBORObject coseKeyMap = CBORObject.NewMap();
        
        coseKeyMap.Add(CBORObject.FromObject(KeyKeys.KeyType.AsCBOR()), KeyKeys.KeyType_Octet);
        coseKeyMap.Add(CBORObject.FromObject(KeyKeys.KeyId.AsCBOR()), kid);
        cnfMap.Add(Constants.COSE_KEY_CBOR, coseKeyMap);
        identityMap.Add(CBORObject.FromObject(Constants.CNF), cnfMap);
        
        // The serialized identity map to use as "psk_identity" in DTLS
        return identityMap.EncodeToBytes();
		
	}
	
    /**
     * Compute a digital signature
     * 
     * @param signKeyCurve   Elliptic curve used to compute the signature
     * @param privKey  private key of the signer, used to compute the signature
     * @param dataToSign  content to sign
     * @return The computed signature
     
     */
    public static byte[] computeSignature(int signKeyCurve, PrivateKey privKey, byte[] dataToSign) {

        Signature signCtx = null;
        byte[] signature = null;

        try {
     	   if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
     		  signCtx = Signature.getInstance("SHA256withECDSA");
     	   else if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
     		  signCtx = Signature.getInstance("NonewithEdDSA", "EdDSA");
     	   else {
     		   // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
     		  Assert.fail("Unsupported signature algorithm");
     	   }
            
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsupported signature algorithm");
        }
        catch (NoSuchProviderException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsopported security provider for signature computing");
        }
        
        try {
            if (signCtx != null)
            	signCtx.initSign(privKey);
            else
                Assert.fail("Signature algorithm has not been initialized");
        }
        catch (InvalidKeyException e) {
            System.out.println(e.getMessage());
            Assert.fail("Invalid key excpetion - Invalid private key");
        }
        
        try {
        	if (signCtx != null) {
        		signCtx.update(dataToSign);
        		signature = signCtx.sign();
        	}
        } catch (SignatureException e) {
            System.out.println(e.getMessage());
            Assert.fail("Failed signature computation");
        }
        
        return signature;
        
    }
    
    /**
     * Verify the correctness of a digital signature
     * 
     * @param signKeyCurve   Elliptic curve used to process the signature
     * @param pubKey   Public key of the signer, used to verify the signature
     * @param signedData   Data over which the signature has been computed
     * @param expectedSignature   Signature to verify
     * @return True if the signature verifies correctly, false otherwise
     */
    public static boolean verifySignature(int signKeyCurve, PublicKey pubKey, byte[] signedData, byte[] expectedSignature) {

        Signature signature = null;
        boolean success = false;
        
        try {
           if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
        	   signature = Signature.getInstance("SHA256withECDSA");
           else if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
        	   signature = Signature.getInstance("NonewithEdDSA", "EdDSA");
           else {
               // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
              Assert.fail("Unsupported signature algorithm");
           }
             
         }
         catch (NoSuchAlgorithmException e) {
             System.out.println(e.getMessage());
             Assert.fail("Unsupported signature algorithm");
         }
         catch (NoSuchProviderException e) {
             System.out.println(e.getMessage());
             Assert.fail("Unsopported security provider for signature computing");
         }
         
         try {
             if (signature != null)
            	 signature.initVerify(pubKey);
             else
                 Assert.fail("Signature algorithm has not been initialized");
         }
         catch (InvalidKeyException e) {
             System.out.println(e.getMessage());
             Assert.fail("Invalid key excpetion - Invalid public key");
         }
         
         try {
             if (signature != null) {
            	 signature.update(signedData);
                 success = signature.verify(expectedSignature);
             }
         } catch (SignatureException e) {
             System.out.println(e.getMessage());
             Assert.fail("Failed signature verification");
         }
         
         return success;

    }
    
}
