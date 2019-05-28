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
package se.sics.ace.coap.rs.oscoreProfile;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;


/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 * 
 * @author Ludwig Seitz
 *
 */
public class OscoreAuthzInfo extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAuthzInfo.class.getName());

    /**
     * Temporary storage for the CNF claim
     */
    private CBORObject cnf;
	
	/**
	 * Constructor.
	 * 
	 * @param tr  a token repository
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 */
	public OscoreAuthzInfo(TokenRepository tr, List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, 
			AudienceValidator audience, CwtCryptoCtx ctx) {
		super(tr, issuers, time, intro, audience, ctx);
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject cbor = null;
        try {
            cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
        } catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        if (!cbor.getType().equals(CBORType.Map)) {
            LOGGER.info("Invalid payload at authz-info: not a cbor map");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        
        CBORObject token = cbor.get(
                CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            LOGGER.info("Missing manadory paramter 'token'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        
        Message reply = super.processToken(token, msg);
        if (reply.getMessageCode() != Message.CREATED) {
            return reply;
        }
        
        if (this.cnf == null) {
            LOGGER.info("Missing required parameter 'cnf'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map); 
        }

        CBORObject nonce = cbor.get(CBORObject.FromObject(Constants.CNONCE));
        if (nonce == null || !nonce.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter type for:"
                    + "'nonce', must be present and byte-string");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map); 
        }
        byte[] n1 = nonce.GetByteString();
        CBORObject osc = this.cnf.get(Constants.OSCORE_Security_Context);
        if (osc == null || !osc.getType().equals(CBORType.Map)) {
            LOGGER.info("Missing or invalid parameter type for "
                    + "'OSCORE_Security_Context', must be CBOR-map");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map); 
        }
        byte[] n2 = new byte[8];
        new SecureRandom().nextBytes(n2);
        byte[] contextId = new byte[n1.length+n2.length];
        System.arraycopy(n1, 0, contextId, 0, n1.length);
        System.arraycopy(n2, 0, contextId, n1.length, n2.length);
                    
        CBORObject algC = osc.get(Constants.OS_ALG);
        AlgorithmID alg = null;
        if (algC != null) {
            try {
                alg = AlgorithmID.FromCBOR(algC);
            } catch (CoseException e) {
                LOGGER.info("Invalid algorithmId: " + e.getMessage());
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        }
        
        CBORObject clientId = osc.get(Constants.OS_CLIENTID);
        byte[] recipient_id = null;
        if (clientId != null) {
            if (!clientId.getType().equals(CBORType.ByteString)) {
                LOGGER.info("Invalid parameter: 'clientId',"
                        + " must be byte-array");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
            recipient_id = clientId.GetByteString(); 
	    }
               
        CBORObject ctxtId = osc.get(Constants.OS_CONTEXTID);
        if (ctxtId != null) {
            LOGGER.info("Invalid parameter: contextID must be null");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
                
        CBORObject kdfC = osc.get(Constants.OS_HKDF);
        AlgorithmID kdf = null;
        if (kdfC != null) {
            try {
                kdf = AlgorithmID.FromCBOR(kdfC);
            } catch (CoseException e) {
                LOGGER.info("Invalid kdf: " + e.getMessage());
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        }
        
        CBORObject ms = osc.get(Constants.OS_MS);
        if (ms == null || !ms.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter: 'master secret',"
                    + " must be byte-array");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        byte[] master_secret = ms.GetByteString();
        
        CBORObject rpl = osc.get(Constants.OS_RPL);
        Integer replay_size = null;
        if (rpl != null) {
            if (!rpl.CanFitInInt32()) {
                LOGGER.info("Invalid parameter: 'replay window size',"
                        + " must be 32-bit integer");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
            replay_size = rpl.AsInt32();
        }

        CBORObject salt = osc.get(Constants.OS_SALT);
        byte[] master_salt = null;
        if (salt != null) {
            if (!salt.getType().equals(CBORType.ByteString)) {
                LOGGER.info("Invalid parameter: 'master salt',"
                        + " must be byte-array");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
            master_salt = salt.GetByteString();
        }

        CBORObject serverId = osc.get(Constants.OS_SERVERID);
        if (serverId == null 
                || !serverId.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter: 'serverId',"
                    + " must be byte-array");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        byte[] sender_id = serverId.GetByteString();
        
        try {
            OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sender_id, 
                    recipient_id, kdf, replay_size, master_salt, contextId);
            HashMapCtxDB db = HashMapCtxDB.getInstance();
            db.addContext(ctx);
            if (msg instanceof CoapReq) {
                CoapReq r = (CoapReq)msg;
                db.addContext(r.getToken(), ctx);
            }
           
        } catch (OSException e) {
            LOGGER.info("Error while creating OSCORE context: " 
                    + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.CNONCE, n2);
        return msg.successReply(reply.getMessageCode(), payload);
	}

	@Override
	protected synchronized void processOther(Map<Short, CBORObject> claims) {
	    super.processOther(claims);
	    this.cnf = claims.get(Constants.CNF);
	}

    @Override
    public void close() throws AceException {
       super.close();
        
    }	
}
