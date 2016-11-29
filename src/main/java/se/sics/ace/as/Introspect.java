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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.Recipient;
import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * The OAuth 2.0 Introspection endpoint.
 * @author Ludwig Seitz
 *
 */
public class Introspect implements Endpoint {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(Introspect.class.getName() );
    
    /**
     * The PDP this endpoint uses to make access control decisions.
     */
    private PDP pdp;
    
    /**
     * The database connector for storing and retrieving stuff.
     */
    private DBConnector db;
    
    /**
     * The time provider for this AS.
     */
    private TimeProvider time;
    
    /**
     * The public key of the AS
     */
    private CBORObject publicKey;
    
    /**
     * Constructor.
     * 
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param publicKey  the public key of the AS or null if there isn't any
     * 
     * @throws AceException  if fetching the cti from the database fails
     */
    public Introspect(PDP pdp, DBConnector db, 
            TimeProvider time, CBORObject publicKey) throws AceException {
        this.pdp = pdp;
        this.db = db;
        this.time = time;
        this.publicKey = publicKey;
    }
    
    
	@Override
    public Message processMessage(Message msg) {
	    //1. Check that this RS is allowed to introspect
	    String id = msg.getSenderId();
        if (!this.pdp.canAccessIntrospect(id)) {
            CBORObject map = CBORObject.NewMap();
            map.Add("error", "unauthorized_client");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized client");
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
	    
	    //2. Purge expired tokens from the database
        try {
            this.db.purgeExpiredTokens(this.time.getCurrentTime());
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

	    
        //parse the token
        AccessToken token;
        try {
            token = parseToken(msg.getRawPayload(), id);
        } catch (AceException e) {
            LOGGER.log(Level.INFO, e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add("error", "must provide non-null token");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }

        
        //3. Check if token is still in there
        //If not return active=false	    
        Map<String, CBORObject> claims;
        try {
            claims = this.db.getClaims(token.getCti());
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        CBORObject payload = CBORObject.NewMap();
        if (claims == null || claims.isEmpty()) {
            try {
                LOGGER.log(Level.INFO, "Returning introspection result: inactive "
                        + "for " + token.getCti());
            } catch (AceException e) {
                LOGGER.severe("Couldn't get cti from CWT: " + e.getMessage());
                return  msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }  
            payload.Add(Constants.ACTIVE, CBORObject.False);           
        } else {
            for (Entry<String, CBORObject> entry : claims.entrySet()) {
                int abbrev = Constants.getAbbrev(entry.getKey());
                if (abbrev == -1) { //No abbreviation found
                    payload.Add(entry.getKey(), entry.getValue());
                } else {
                    payload.Add(abbrev, entry.getValue());
                }
                try {
                    LOGGER.log(Level.INFO, "Returning introspection result: " 
                            + claims.toString() + " for " + token.getCti());
                } catch (AceException e) {
                    LOGGER.severe("Couldn't get cti from CWT: " + e.getMessage());
                    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
            }
            payload.Add(Constants.ACTIVE, CBORObject.True);
        }
        
        return msg.successReply(Message.CREATED, payload);
	}
    
    /**
     * Parses a CBOR object presumably containing an access token.
     * 
     * @param raw  the raw payload
     * @param rsid  the RS identifier
     * 
     * @return  the parsed access token
     * 
     * @throws AceException 
     */
    public AccessToken parseToken(byte[] raw, String rsid) throws AceException {
        if (raw == null) {
            throw new AceException("Access token parser indata was null");
        }
        CBORObject cbor = CBORObject.DecodeFromBytes(raw);
        if (cbor.getType().equals(CBORType.Array)) {
            try {
                CwtCryptoCtx ctx = makeCtx(rsid);
                return CWT.processCOSE(cbor.EncodeToBytes(), ctx);
            } catch (Exception e) {
                LOGGER.severe("Error while processing CWT: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
        } else if (cbor.getType().equals(CBORType.TextString)) {
            return ReferenceToken.parse(cbor);
        }
        throw new AceException("Unknown access token format");        
    }
    
    /**
     * Create a  CWT crypto context for the given RS.
     * 
     * @param rsid  the identifier of the RS
     * 
     * @return  the CWT crytpo context
     * @throws CoseException 
     * @throws AceException 
     */
    private CwtCryptoCtx makeCtx(String rsid) 
            throws AceException, CoseException {
        COSEparams cose = this.db.getSupportedCoseParams(rsid);
        if (cose == null) {
            return null;
        }
        MessageTag tag = cose.getTag();
        switch (tag) {
        case Encrypt:
            return CwtCryptoCtx.encrypt(makeRecipient(cose, rsid), 
                   cose.getAlg().AsCBOR());
        case Encrypt0:
            byte[] ekey = this.db.getRsPSK(rsid);
            if (ekey == null) {
                return null;
            }
            return CwtCryptoCtx.encrypt0(ekey, cose.getAlg().AsCBOR());
        case MAC:
            return CwtCryptoCtx.mac(makeRecipient(cose, rsid), 
                    cose.getAlg().AsCBOR());
        case MAC0:
            byte[] mkey = this.db.getRsPSK(rsid);
            if (mkey == null) {
                return null;
            }
            return CwtCryptoCtx.mac0(mkey, cose.getAlg().AsCBOR());
        case Sign:
            // Access tokens with multiple signers not supported
            return null;
        case Sign1:
            return CwtCryptoCtx.sign1Verify(this.publicKey, 
                    cose.getAlg().AsCBOR());
        default:
            throw new IllegalArgumentException("Unknown COSE message type");
        }
    }
    
    /**
     * Creates the singleton list of recipients for MAC and Encrypt messages.
     * 
     * @param cose  the cose parameters
     * @param rsid  the RS identifier
     * 
     * @return  the recipients list
     * @throws AceException 
     */
    private List<Recipient> makeRecipient(COSEparams cose, String rsid) 
            throws AceException {
        Recipient rs = new Recipient();  
        rs.addAttribute(HeaderKeys.Algorithm, 
             cose.getKeyWrap().AsCBOR(), Attribute.UnprotectedAttributes);
        CBORObject key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
                this.db.getRsPSK(rsid)));
        rs.SetKey(key); 
        return Collections.singletonList(rs);
    }
    
}
