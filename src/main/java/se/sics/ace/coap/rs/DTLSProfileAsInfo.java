package se.sics.ace.coap.rs;

import java.util.Arrays;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;

/**
 * This datastructure contains the information the RS returns to a client in 
 * response to an unauthorized request (regardless of whether it was 4.01, 
 * 4.03 or 4.05).
 * 
 * @author Ludwig Seitz
 *
 */
public class DTLSProfileAsInfo {

    /**
     * The nonce for replay protection
     */
    private byte[] nonce;
    
    /**
     * The absolute URI of the AS
     */
    private String asUri;
    
    
    /**
     * The CBOR abbreviation for "AS"
     */
    private static CBORObject AS = CBORObject.FromObject(0);
    
    /**
     * The CBOR abbreviation for "nonce"
     */
    private static CBORObject NONCE = CBORObject.FromObject(5);
    
    /**
     * Constructor with nonce.
     * 
     * @param asUri  the absolute URI of the AS
     * @param nonce  the nonce for time synchronization
     */
    public DTLSProfileAsInfo(String asUri, byte[] nonce) {
        if (asUri == null || asUri.isEmpty()) {
            throw new IllegalArgumentException(
                    "Cannot create an DTLSProfileAsInfo object "
                    + "with null or empty asUri field");
        }
        this.asUri = asUri;
        this.nonce = Arrays.copyOf(nonce, nonce.length);
    }
    
    /**
     * Constructor without a nonce.
     * 
     * @param asUri  the absolute URI of the AS
     */
    public DTLSProfileAsInfo(String asUri) {
        this(asUri, null);
    }

    /** 
     * @return  the nonce associated with this AS information or null
     * if there is none
     */
    public byte[] getNonce() {
        return this.nonce;
    }

    /**
     * @return  the absolute URI of the AS
     */
    public String getAsUri() {
        return this.asUri;
    }
    
    /**
     * @return  the CBOR encoding of this AS info
     */
    public CBORObject getCBOR() {
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(AS, this.asUri);
        if (this.nonce != null) {
            cbor.Add(NONCE, this.nonce);
        }
        return cbor;
    }
    
    /**
     * Parse the raw bytes of an AS info.
     * 
     * @param raw  the raw bytes
     * 
     * @return  the resulting DTLSProfileAsInfo object
     * @throws AceException 
     */
    public static DTLSProfileAsInfo parse(byte[] raw) throws AceException {
       CBORObject cbor = CBORObject.DecodeFromBytes(raw);
       if (!cbor.getType().equals(CBORType.Map)) {
           throw new AceException("Malformed AS-info object");
       }
       CBORObject asC = cbor.get(AS);
       if (asC == null || !asC.getType().equals(CBORType.TextString)) {
           throw new AceException("Malformed AS-info object");
       }
       String asUri = asC.AsString();
       CBORObject nonceC = cbor.get(NONCE);
       byte[] nonce = null;
       if (nonceC != null) {
           if (!nonceC.getType().equals(CBORType.ByteString)) {
               throw new AceException("Malformed AS-info object");
           }
           nonce = nonceC.GetByteString();
       }
       return new DTLSProfileAsInfo(asUri, nonce);
    }

}
