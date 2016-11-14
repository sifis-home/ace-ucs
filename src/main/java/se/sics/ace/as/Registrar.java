/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.as;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.Recipient;

import se.sics.ace.COSEparams;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * This class interacts with the database to 
 * store and retrieve information about the clients and RS that are registered at this AS.
 * 
 * Note: Each RS is automatically assigned to a singleton audience that corresponds to its
 * identifier.
 * 
 * @author Ludwig Seitz
 *
 */
public class Registrar {
	
	/**
	 * Tries to find a common PSK for the given audience.
	 * 
	 * @param aud  the audience
	 * @return  a common PSK or null if there isn't any
	 */
	private byte[] getCommonSecretKey(String aud) {
	    Set<String> rss = this.aud2rs.get(aud);
	    byte[] key = null;
	    for (String rs : rss) {
	       if (getSecretKey(rs) == null) {
	           return null;
	       }
	       if (key == null) {
	           key = Arrays.copyOf(getSecretKey(rs), getSecretKey(rs).length);
	       } else {
	           if (!Arrays.equals(key, getSecretKey(rs))) {
	               return null;
	           }
	       }
	    }
	    return key;
	}
	
	/**
	 * Tries to find a common MAC/Sign/Encrypt algorithm for the given audience.
	 * 
	 * @param aud  the audience
	 * @return  the algorithms identifier or null if there isn't any
	 */
	private AlgorithmID getCommonAlgId(String aud) {
	    Set<String> rss = this.aud2rs.get(aud);
        AlgorithmID alg = null;
        for (String rs : rss) {
           if (alg == null) {
               alg = this.coseEncoding.get(rs).getAlg();
           } else {
               if (!alg.equals(this.coseEncoding.get(rs).getAlg())) {
                   return null;
               }
           }
        }
        return alg;
	}
	
	/**
	 * Create a recipient list for an audience.
	 * 
	 * @param aud  the audience
	 * @return  the recipient list
	 */
	private List<Recipient> makeRecipients(String aud) {
	    List<Recipient> rl = new ArrayList<>();
	    for (String rs : this.aud2rs.get(aud)) {
	        Recipient r = new Recipient();
	        r.addAttribute(HeaderKeys.Algorithm, 
	                this.coseEncoding.get(rs).getKeyWrap().AsCBOR(), 
	                Attribute.UnprotectedAttributes);
	        CBORObject key = CBORObject.NewMap();
	        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
	        key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
	                this.secretKeys.get(rs)));
	        r.SetKey(key); 
	        rl.add(r);
	    }
	    return rl;
	}
}
