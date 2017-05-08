/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
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
package se.sics.ace.coap.rs.dtlsProfile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.rs.ScopeValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * This extends the TokenRepository with functionality to map SenderIdentity to the
 * kid of the token.
 * 
 * @author Ludwig Seitz
 *
 */
public class DtlspTokenRepository extends TokenRepository {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DtlspTokenRepository.class.getName());
    
    /**
     * The mapping of SenderIdentity to kid
     */
    private Map<String, String> sid2kid;
    
    /**
     * The singleton instance of this repo
     */
    private static DtlspTokenRepository singleton;
    
    /**
     * The singleton getter
     * @return  the singleton repository
     * @throws AceException  if the repository is not initialized
     */
    public static DtlspTokenRepository getInstance() 
            throws AceException {
        if (singleton == null) {
            throw new AceException("Token repository not created");
        }
        return singleton;
    }
    
    /**
     * Creates the one and only instance of the token repo and loads the 
     * existing tokens from a JSON file is there is one.
     * 
     * The JSON file stores the tokens as a JSON array of JSON maps,
     * where each map represents the claims of a token, String mapped to
     * the Base64 encoded byte representation of the CBORObject.
     * 
     * @param scopeValidator  the application specific scope validator
     * @param tokenFile  the file storing the existing tokens, if the file
     *     does not exist it is created
     * @param ctx  the crypto context for reading encrypted tokens
     * 
     * @param scopeValidator
     * @param tokenFile
     * @param ctx
     * @throws AceException
     * @throws IOException
     */
    public static void create(ScopeValidator scopeValidator, 
            String tokenFile, CwtCryptoCtx ctx) 
                    throws AceException, IOException {
        if (singleton != null) {
            throw new AceException("Token repository already exists");
        }
        singleton = new DtlspTokenRepository(
                scopeValidator, tokenFile, ctx);
    }
   

    /**
     * Creates the token repository and loads the existing tokens
     * from a JSON file if there is one.
     * 
     * The JSON file stores the tokens as a JSON array of JSON maps,
     * where each map represents the claims of a token, String mapped to
     * the Base64 encoded byte representation of the CBORObject.
     * 
     * @param scopeValidator  the application specific scope validator
     * @param tokenFile  the file storing the existing tokens, if the file
     *     does not exist it is created
     * @param ctx  the crypto context for reading encrypted tokens
     *   
     * @throws IOException 
     * @throws AceException 
     */
    protected DtlspTokenRepository(ScopeValidator scopeValidator, 
            String tokenFile, CwtCryptoCtx ctx)
            throws IOException, AceException {
        super(scopeValidator, tokenFile, ctx);
        this.sid2kid = new HashMap<>();
    }
    
    /**
     * Add a new Access Token to the repo.  Note that this method DOES NOT 
     * check the validity of the token.
     * 
     * @param claims  the claims of the token
     * @param ctx  the crypto context of this RS  
     * 
     * @return  the cti or the local id given to this token
     * 
     * @throws AceException 
     * @throws CoseException 
     */
    @Override
    public synchronized CBORObject addToken(Map<String, CBORObject> claims, 
            CwtCryptoCtx ctx) throws AceException {
                CBORObject ret = super.addToken(claims, ctx);
                String cti = new String(ret.GetByteString());
                String kid = super.cti2kid.get(cti);
                OneKey key = super.kid2key.get(kid);
                String sid = makeSid(key);
                this.sid2kid.put(sid, kid);
                return ret;
    }

    /**
     * Create a SubjectIdentity for DTLS out of a OneKey.
     * 
     * @param key  the key
     * 
     * @return  the generated SubjectIdentity
     * 
     * @throws AceException
     */
    public static String makeSid(OneKey key) throws AceException {
        if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_Octet)) {
            //We have a symmetric key, assume kid == Sid
            CBORObject kid = key.get(KeyKeys.KeyId);
            if (kid == null || !kid.getType().equals(CBORType.ByteString)) {
                LOGGER.severe("Key doesn't have valid kid in makeSid()");
                throw new AceException("Key doesn't have valid kid");
            }
            return new String(kid.GetByteString());    
        } else if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2)) {
            //We have an asymmetric key
            try {
                RawPublicKeyIdentity rpkId 
                    = new RawPublicKeyIdentity(key.AsPublicKey());
                return rpkId.getName();
            } catch (CoseException e) {
                LOGGER.severe("Error while creating RPK identity: " 
                        + e.getMessage());
                throw new AceException(e.getMessage());
            }
        } else {
            LOGGER.severe("Unknown key type: " 
                    + key.get(KeyKeys.KeyType).toString());
            throw new AceException("Unknown key type");
        }
    }
    
    /**
     * Returns the kid used by a SubjectIdentity.
     * 
     * @param sid  the SubjectIdentity from DTLS
     * @return  the kid or null if we don't have this key

     */
    public String getKid(String sid) {
        return this.sid2kid.get(sid);
    }
    
    /**
     * Manually set the sid to kid relation.
     * 
     * @param sid
     * @param kid
     */
    public void setSid2Kid(String sid, String kid) {
        this.sid2kid.put(sid, kid);
    }
}
