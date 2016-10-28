/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
package se.sics.ace;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.MessageTag;

/**
 * General parameters of a COSE Message (i.e. not including message specific
 * ones like key and IV).
 * 
 * @author Ludwig Seitz
 *
 */
public class COSEparams {
    
    /**
     * Identifies the type of COSE message
     */
    private MessageTag tag;
    
    /**
     * Identifies the main algorithm
     */
    private AlgorithmID alg;
    
    /**
     * Identifies the key wrapping method
     */
    private AlgorithmID keyWrap;
    
    
    /**
     * Constructor.
     * 
     * @param tag  the message type (MAC, MAC0, Sign1, Sign, ...)
     * @param alg  the main algorithm (HMAC_SHA_256, AES_CCM_16_64_128, ...)
     * @param keyWrap  the key wrap algorithm (Direct, AES_KW_128, ...)
     */
    public COSEparams(MessageTag tag, AlgorithmID alg, AlgorithmID keyWrap) {
        this.tag = tag;
        this.alg = alg;
        this.keyWrap = keyWrap;
    }

    /**
     * @return  the message type (MAC, MAC0, Sign1, Sign, ...)
     */
    public MessageTag getTag() {
        return this.tag;
    }

    /**
     * @return   the main algorithm (HMAC_SHA_256, AES_CCM_16_64_128, ...)
     */
    public AlgorithmID getAlg() {
        return this.alg;
    }


    /**
     * @return  the key wrap algorithm (Direct, AES_KW_128, ...)
     */
    public AlgorithmID getKeyWrap() {
        return this.keyWrap;
    }
    
    @Override
    public String toString() {
        return new String(this.tag.value + ":" + this.alg.AsCBOR().AsInt32() 
                + ":" + this.keyWrap.AsCBOR().AsInt16());
    }
    
    /**
     * Parse an encoded set of COSE message parameters.
     * 
     * @param encoded  the encoded String.
     * @return  the parsed parameter object
     * @throws NumberFormatException
     * @throws CoseException
     */
    public static COSEparams parse(String encoded) 
                throws NumberFormatException, CoseException {
        String[] params = encoded.split(":");
        if (params.length != 3) {
            throw new IllegalArgumentException(
                    "Not an encoded set of COSE message parameters");
        }
        return new COSEparams(
                MessageTag.FromInt(Integer.valueOf(params[0])),
                AlgorithmID.FromCBOR(CBORObject.FromObject(
                        Integer.valueOf(params[1]))),
                AlgorithmID.FromCBOR(CBORObject.FromObject(
                        Integer.valueOf(params[2]))));
                
    }
    
    @Override
    public boolean equals(Object cose) {
        if (cose instanceof COSEparams) {
            COSEparams foo = (COSEparams)cose;
            if (this.tag.value != foo.tag.value) {
                return false;
            }
            if (this.alg.compareTo(foo.alg) != 0) {
                return false;
            }
            if (this.keyWrap.compareTo(foo.keyWrap) != 0) {
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return 10000*this.tag.value + 100*this.alg.AsCBOR().AsInt32() 
                + this.keyWrap.AsCBOR().AsInt32();
    }
    
}
