/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
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
     * Boolean for verify
     */
    private static boolean verify = true;
    
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
     * The asymmetric key pair of the AS
     */
    private OneKey keyPair;
    
    /**
     * Constructor.
     * 
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param keyPair the asymmetric key pair of the AS or null
     *
     * @throws AceException  if fetching the cti from the database fails
     */
    public Introspect(PDP pdp, DBConnector db, 
            TimeProvider time, OneKey keyPair) throws AceException {
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
        this.keyPair = keyPair;
    }
    
    
	@Override
    public Message processMessage(Message msg) {
	    if (msg == null) {//This should not happen
            LOGGER.severe("Introspect.processMessage() received null message");
            return null;
        }
	    LOGGER.log(Level.INFO, "Introspect received message: " 
	            + msg.getParameters());
        	    
	    //1. Check that this RS is allowed to introspect	    
	    String id = msg.getSenderId();
        PDP.IntrospectAccessLevel accessLevel;
        try {
            accessLevel = this.pdp.getIntrospectAccessLevel(id);
            if (accessLevel.equals(PDP.IntrospectAccessLevel.NONE)) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "unauthorized client: " + id);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
	    
	    //2. Purge expired tokens from the database
        try {
            this.db.purgeExpiredTokens(this.time.getCurrentTime());
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }

	    //Get the token from the payload
        CBORObject tokenAsCborByteArray = msg.getParameter(Constants.TOKEN);
        if (tokenAsCborByteArray == null) {
            LOGGER.log(Level.INFO,
                    "Request didn't provide 'token' parameter");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Must provide 'token' parameter");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        CBORObject tokenAsCbor = CBORObject.DecodeFromBytes(
                tokenAsCborByteArray.GetByteString());

        //parse the token
        AccessToken token;
        try {
            token = parseToken(tokenAsCbor, id);
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
                LOGGER.log(Level.INFO, 
                        "Returning introspection result: inactive "
                        + "for " + token.getCti());
            } catch (AceException e) {
                LOGGER.severe("Couldn't get cti from CWT: " + e.getMessage());
                return  msg.failReply
                        (Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }  
            payload.Add(Constants.ACTIVE, CBORObject.False);
            //No need to check for client token, the token is invalid anyways
            return msg.successReply(Message.CREATED, payload); 
        }

        // The NONE option was checked above. Check if we have claims access, 
        // or only to the activeness of the token.
        if (accessLevel.equals(PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS))
        {
            // We have access to all claims; add them to reply.
            payload = Constants.getCBOR(claims);
        }
        else
        {
            // Only access tnot vo activeness.
            payload = CBORObject.NewMap();
        }

        payload.Add(Constants.ACTIVE, CBORObject.True);

        try {
            LOGGER.log(Level.INFO, "Returning introspection result: " 
                    + payload.toString() + " for " + token.getCti());
        } catch (AceException e) {
            LOGGER.severe("Couldn't get cti from CWT: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        return msg.successReply(Message.CREATED, payload);
	}

    /**
     * Parses a CBOR object presumably containing an access token.
     * 
     * @param token  the object
     * @param senderId  the sender's id from the secure connection
     * 
     * @return  the parsed access token
     * 
     * @throws AceException 
     */
    public AccessToken parseToken(CBORObject token, String senderId)
            throws AceException {
        if (token == null) {
            throw new AceException("Access token parser indata was null");
        }
        if (token.getType().equals(CBORType.Array)) {
            try {
                // Get the RS id (audience) from the COSE KID header.
            	org.eclipse.californium.cose.Message coseRaw = org.eclipse.californium.cose.Message.DecodeFromBytes(
                        token.EncodeToBytes());
                CBORObject kid = coseRaw.findAttribute(HeaderKeys.KID);
                Set<String> aud = new HashSet<>();
                if(kid == null) {
                    if (senderId == null) {
                        throw new AceException("Cannot determine Audience"
                                + "of the token for introspection");
                    }
                    aud.add(senderId);
                } else {
                    CBORObject audArray = CBORObject.DecodeFromBytes(
                            kid.GetByteString());
                    for (int i=0; i<audArray.size();i++) {
                        aud.add(audArray.get(i).AsString());
                    }
                }            
                CwtCryptoCtx ctx = EndpointUtils.makeCommonCtx(aud, this.db,
                        this.keyPair, verify);
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


    @Override
    public void close() throws AceException {
        this.db.close();        
    }
    
}
