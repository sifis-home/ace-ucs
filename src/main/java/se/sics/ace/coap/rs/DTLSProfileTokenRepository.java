package se.sics.ace.coap.rs;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
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
public class DTLSProfileTokenRepository extends TokenRepository {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DTLSProfileTokenRepository.class.getName());
    
    /**
     * The mapping of SenderIdentity to kid
     */
    private Map<String, String> sid2kid;

    /**
     * Creates the token repository and loads the existing tokens
     * from a JSON file if there is one.
     * 
     * The JSON file stores the tokens as a JSON array of JSON maps,
     * where each map represents the claims of a token, String mapped to
     * the Base64 encoded byte representation of the CBORObject.
     * 
     * @param scopeValidator  the application specific scope validator
     * @param resources  the resources this TokenRepository serves 
     * @param tokenFile  the file storing the existing tokens, if the file
     *     does not exist it is created
     * @param ctx  the crypto context for reading encrypted tokens
     *   
     * @throws IOException 
     * @throws AceException 
     */
    public DTLSProfileTokenRepository(ScopeValidator scopeValidator,
            Set<String> resources, String tokenFile, CwtCryptoCtx ctx)
            throws IOException, AceException {
        super(scopeValidator, resources, tokenFile, ctx);
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
    public CBORObject addToken(Map<String, CBORObject> claims, 
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
    private static String makeSid(OneKey key) throws AceException {
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
}
