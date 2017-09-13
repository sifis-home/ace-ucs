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
package se.sics.ace.as;

import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MessageTag;
import COSE.OneKey;
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
public class Introspect implements Endpoint, AutoCloseable {
    
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
    private OneKey publicKey;
    
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
            TimeProvider time, OneKey publicKey) throws AceException {
        if (pdp == null) {
            LOGGER.severe("Introspect endpoint's PDP was null");
            throw new AceException(
                    "Introspect endpoint's PDP must be non-null");
        }
        if (db == null) {
            LOGGER.severe("Introspect endpoint's DBConnector was null");
            throw new AceException(
                    "Introspect endpoint's DBConnector must be non-null");
        }
        if (time == null) {
            LOGGER.severe("Introspect endpoint received a null TimeProvider");
            throw new AceException(
                    "Introspect endpoint requires a non-null TimeProvider");
        }
        this.pdp = pdp;
        this.db = db;
        this.time = time;  
        this.publicKey = publicKey;
    }
    
    
	@Override
    public Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "Introspect received message: " 
	            + msg.getParameters());
        	    
	    //1. Check that this RS is allowed to introspect	    
	    String id = msg.getSenderId();
        if (!this.pdp.canAccessIntrospect(id)) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized client: " + id);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
	    
	    //2. Purge expired tokens from the database
        try {
            this.db.purgeExpiredTokens(this.time.getCurrentTime());
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

	    //Get the token from the payload
        CBORObject cbor = msg.getParameter(Constants.TOKEN);
        if (cbor == null) {
            LOGGER.log(Level.INFO,
                    "Request didn't provide 'token' parameter");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Must provide 'token' parameter");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }

        CBORObject cborAudience = msg.getParameter((short)40);
        if(cborAudience != null)
        {
            id = cborAudience.AsString();
        }

        //parse the token
        AccessToken token;
        try {
            token = parseToken(cbor, id);
        } catch (AceException e) {
            LOGGER.log(Level.INFO, e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "must provide non-null token");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }

        
        //3. Check if token is still in there
        //If not return active=false	    
        Map<Short, CBORObject> claims;
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
            //No need to check for client token, the token is invalid anyways
            return msg.successReply(Message.CREATED, payload); 
        }
        payload = Constants.getCBOR(claims);
        payload.Add(Constants.ACTIVE, CBORObject.True);
        try {
            LOGGER.log(Level.INFO, "Returning introspection result: " 
                    + payload.toString() + " for " + token.getCti());
        } catch (AceException e) {
            LOGGER.severe("Couldn't get cti from CWT: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

           
        //Check if we need to generate a client token
        // ... to do this find the client holding this token
        CBORObject ctiCB = claims.get(Constants.CTI);
        if (ctiCB == null) {
            LOGGER.severe("Token has no cti");
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        if (!ctiCB.getType().equals(CBORType.ByteString)) {
            LOGGER.severe("Token has invalid cti");
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        String cti = Base64.getEncoder().encodeToString(
                ctiCB.GetByteString());
        try {
            String clientId = this.db.getClient4Cti(cti);
            if (clientId == null) {
                LOGGER.severe("Token: " + cti + " has no owner");
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
            if (this.db.needsClientToken(clientId)) {
                payload.Add(Constants.CLIENT_TOKEN, 
                        generateClientToken(claims, clientId, cti, id));
            }
        } catch (AceException e) {
            LOGGER.severe("Error while querying need for client token: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        return msg.successReply(Message.CREATED, payload);
	}
    
	/**
	 * Generate a client token from the claims of an access token
	 * @param claims  the claims of the access token
	 * @param clientId  the client identifier
	 * @param cti  the token identifier
	 * @param rsId  the RS identifier
	 * 
	 * @return the client token
	 * @throws AceException 
	 */
    private CBORObject generateClientToken(
            Map<Short, CBORObject> claims, String clientId, String cti, 
            String rsId) throws AceException {
        CBORObject ct = CBORObject.NewMap();        
        CBORObject aud = claims.get(Constants.AUD);
        Set<String> audSet = new HashSet<>();
        if (aud == null) {
            audSet.add(this.db.getDefaultAudience(clientId));  
        } else if (aud.getType().equals(CBORType.Array)) {
            for (int i=0; i<aud.size(); i++) {
                CBORObject audE = aud.get(i);
                if (audE.getType().equals(CBORType.TextString)) {
                    audSet.add(audE.AsString());
                } //XXX: Silently skip non-text string audiences
            }   
        } else if (aud.getType().equals(CBORType.TextString)) {
            audSet.add(aud.AsString());  
        } else {//error
            LOGGER.warning("Audience is malformed for token: " + cti);
            throw new AceException("Audience malformed");
        }
        
        if (audSet.isEmpty()) {
            throw new AceException("Token: " + cti + " has no audience");
        }
        
        //Get the client's key
        OneKey cpsk = this.db.getCPSK(clientId);
        OneKey crpk = this.db.getCRPK(clientId);
        
        if (cpsk == null && crpk == null) {
            throw new AceException("Client: " + clientId + " has no keys");
        }        
        
        String popType = this.db.getSupportedPopKeyType(clientId, audSet);
        switch(popType) {
        case "RPK":
            //Get RS key
            OneKey rpk = this.db.getRsRPK(rsId);
            if (rpk == null) {
                throw new AceException("RS: " + rsId 
                        + " has no raw public key, but supports RPK key type");
            }
            ct.Add(Constants.RS_CNF, rpk.AsCBOR());
            //Get client's kid
            if (crpk == null) {
                throw new AceException("Client: " + clientId 
                        + " has no raw public key, but supports RPK key type");
            }
            CBORObject kid = crpk.get(KeyKeys.KeyId);
            if (kid == null) {
                throw new AceException("Client's: " + clientId 
                        + " raw public key has no kid");
            }
            //We only need the kid for the client's public key
            CBORObject cnf = CBORObject.NewMap();
            cnf.Add(Constants.COSE_KID_CBOR, kid);
            ct.Add(Constants.CNF, cnf);
            break;
        case "PSK":
            //Take the cnf from the claims
            cnf = claims.get(Constants.CNF);
            if (cnf == null) {
                throw new AceException("Token: " + cti + " has no 'cnf' claim");
            }
            ct.Add(Constants.CNF, cnf);
            break;
        default :
            throw new AceException("Unsupported pop-key type: " + popType
                    + " for token: " + cti);
        }
        
        String profile = this.db.getSupportedProfile(clientId, audSet);
        if (profile == null) {
            throw new AceException("Client: " + clientId + " and audiences: "
                    + audSet.toString() + " do not support a common profile");
        }
        ct.Add(Constants.PROFILE, CBORObject.FromObject(profile));
        
        if (cpsk == null) {
            //XXX: Client token is currently implemented for client PSK only
            throw new AceException("Client token with client RPK only is"
                    + " currently not supported");   
        }
        CBORObject encC = null;     
        Encrypt0Message enc = new Encrypt0Message();
        //Find the right algorithm from the key length
        byte[] ckey = cpsk.get(KeyKeys.Octet_K).GetByteString();
        try {
            switch (ckey.length) {
            case 16:

                enc.addAttribute(HeaderKeys.Algorithm, 
                        AlgorithmID.AES_CCM_64_64_128.AsCBOR(), 
                        Attribute.PROTECTED);

                break;
            case 32:
                enc.addAttribute(HeaderKeys.Algorithm, 
                        AlgorithmID.AES_CCM_64_64_256.AsCBOR(), 
                        Attribute.PROTECTED);
                break;
            default:
                throw new AceException("Unsupported key length for client: "
                        + clientId);
            }
            enc.SetContent(ct.EncodeToBytes());
            enc.encrypt(cpsk.get(KeyKeys.Octet_K).GetByteString());
            encC = enc.EncodeToCBORObject();
        } catch (CoseException | IllegalStateException 
                | InvalidCipherTextException e) {
           LOGGER.severe("Error while encrypting client token: " 
                + e.getMessage());
           throw new AceException("Error while encrypting client token");
        }
        return encC;
    }


    /**
     * Parses a CBOR object presumably containing an access token.
     * 
     * @param token  the object
     * @param rsid  the RS identifier
     * 
     * @return  the parsed access token
     * 
     * @throws AceException 
     */
    public AccessToken parseToken(CBORObject token, String rsid) 
            throws AceException {
        if (token == null) {
            throw new AceException("Access token parser indata was null");
        }
     
        if (token.getType().equals(CBORType.Array)) {
            try {
                CwtCryptoCtx ctx = makeCtx(rsid);
                return CWT.processCOSE(token.EncodeToBytes(), ctx);
            } catch (Exception e) {
                LOGGER.severe("Error while processing CWT: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
        } else if (token.getType().equals(CBORType.ByteString)) {
            return ReferenceToken.parse(token);
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
        COSEparams cose = this.db.getSupportedCoseParams(
                Collections.singleton(rsid));
        if (cose == null) {
            return null;
        }
        MessageTag tag = cose.getTag();
        switch (tag) {
        case Encrypt:
            return CwtCryptoCtx.encrypt(makeRecipient(cose, rsid), 
                   cose.getAlg().AsCBOR());
        case Encrypt0:
            OneKey ek = this.db.getRsPSK(rsid);
            byte[] ekey = ek.get(KeyKeys.Octet_K).GetByteString();
            if (ekey == null) {
                return null;
            }
            return CwtCryptoCtx.encrypt0(ekey, cose.getAlg().AsCBOR());
        case MAC:
            return CwtCryptoCtx.mac(makeRecipient(cose, rsid), 
                    cose.getAlg().AsCBOR());
        case MAC0:
            OneKey mk = this.db.getRsPSK(rsid);
            byte[] mkey = mk.get(KeyKeys.Octet_K).GetByteString();
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
     * @throws CoseException 
     */
    private List<Recipient> makeRecipient(COSEparams cose, String rsid) 
            throws AceException, CoseException {
        Recipient rs = new Recipient();  
        rs.addAttribute(HeaderKeys.Algorithm, 
             cose.getKeyWrap().AsCBOR(), Attribute.UNPROTECTED);
        CBORObject key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
                this.db.getRsPSK(rsid)));
        OneKey coseKey = new OneKey(key);
        rs.SetKey(coseKey); 
        return Collections.singletonList(rs);
    }


    @Override
    public void close() throws AceException {
        this.db.close();        
    }
    
}
