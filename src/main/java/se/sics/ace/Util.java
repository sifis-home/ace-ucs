package se.sics.ace;

import java.util.Base64;

import com.upokecenter.cbor.CBORObject;

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
	
    /**
     * Build the _deterministic_ CBOR map to use as DTLS "psk_identity"
     * and return a string as its Base64 serialization
     *  
     * @param kid   The 'kid' of the key used as PoP key
     * 
     * @return The string to use as "psk_identity" in DTLS
     */
	public static String buildDtlsPskIdentity(byte[] kid) {
        
		/*
		 * The goal is to deterministically produce this CBOR map
		 * (the considered 'kid' value is just an example)
		 * 
		 * 
		 
		   { cnf : {
		      COSE_Key : {
		         kty: symmetric,
		         kid : h'3d027833fc6267ce'   ; 'kid' value
		       }
		     }
		   }
		   
		   The above must result in the serialized map below, using the following CBOR abbreviations:
		   	- 0x08 for "cnf"
 		   	- 0x01 for "COSE_Key"
 		   	- 0x01 for "kty"
 		   	- 0x04 for "symmetric"
 		   	- 0x02 for "kid"
 		   	
			A1                           # map(1)
			   08                        # unsigned(8)
			   A1                        # map(1)
			      01                     # unsigned(1)
			      A2                     # map(2)
			         01                  # unsigned(1)
			         04                  # unsigned(4)
			         02                  # unsigned(2)
			         48                  # bytes(8)
			            3D027833FC6267CE 
			   
		 *
		 *
		 */
      
        byte[] fixedBytes = new byte[] {(byte) 0xa1, (byte) 0x08, (byte) 0xa1, (byte) 0x01,
        		                        (byte) 0xa2, (byte) 0x01, (byte) 0x04, (byte) 0x02};
        
        byte[] serializedKidCbor = CBORObject.FromObject(kid).EncodeToBytes();
        
        byte[] serializedIdentityMap = new byte[fixedBytes.length + serializedKidCbor.length];
        
        // Copy the well known bytes
        System.arraycopy(fixedBytes, 0, serializedIdentityMap, 0, fixedBytes.length);
        
        // Copy the encoding of the CBOR byte string with value the 'kid' of the PoP key
        System.arraycopy(serializedKidCbor, 0, serializedIdentityMap, fixedBytes.length, serializedKidCbor.length);
        
        // Return the Based64-encoded string of the serialized identity map, to use as "psk_identity" in DTLS
        String pskIdentity = Base64.getEncoder().encodeToString(serializedIdentityMap);
        return pskIdentity;
		
	}
    
}
