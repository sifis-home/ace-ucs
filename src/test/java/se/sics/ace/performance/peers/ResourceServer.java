package se.sics.ace.performance.peers;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.AccessTokenFactory;

import java.util.*;

public class ResourceServer {
    private final String name;
    private final String scope;
    private final String aud;

    private final byte[] sId;
    private final byte[] masterSecret;
    private final byte[] tokenKey;
    private Set<String> keyTypes = new HashSet<String>(){{add("PSK");}};
    private Set<String> profiles = new HashSet<String>(){{add("coap_oscore");}};
    private Set<Short> tokenTypes = new HashSet<Short>(){{add(AccessTokenFactory.CWT_TYPE);}};
    private Set<COSEparams> cose =
            new HashSet<COSEparams>(){{add(new COSEparams(MessageTag.Encrypt0,
                    AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct));}};
    private long expiration = 86400000L;

    private final OneKey sharedPsk;
    private final OneKey tokenPsk;
    private final OneKey publicKey = null;


    public ResourceServer (String name, String scope,
                   String aud, String sId, String masterSecret, String tokenKey)
            throws AceException {
        if (name == null || scope == null || aud == null || sId == null || masterSecret == null) {
            throw new AceException("Peer requires non-null parameters");
        }
        this.name = name;
        this.scope = scope;
        this.aud = aud;
        this.sId = hexStringToByteArray(sId);

        this.masterSecret = masterSecret.getBytes(Constants.charset);
        this.tokenKey = tokenKey.getBytes(Constants.charset);
        try {
            this.sharedPsk = generateKey(this.masterSecret);
            this.tokenPsk = generateKey(this.tokenKey);
        } catch (CoseException e) {
            throw new RuntimeException(e);
        }
    }

    public String getName() {
        return name;
    }

    public String getScope() {
        return scope;
    }

    public Set<String> getScopeSet() {
        return new HashSet<>(Arrays.asList(this.scope.split(" ")));
    }

    public Set<String> getAudSet() {
        return new HashSet<>(Arrays.asList(this.aud.split(" ")));
    }

    public String getAud() {
        return aud;
    }

    public byte[] getsId() {
        return sId;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public OneKey getSharedPsk() {
        return sharedPsk;
    }

    public byte[] getTokenKey() {
        return tokenKey;
    }

    public OneKey getTokenPsk() {
        return tokenPsk;
    }

    public OneKey getPublicKey() {
        return publicKey;
    }

    public Set<String> getKeyTypes() {
        return keyTypes;
    }

    public void setKeyTypes(Set<String> keyTypes) {
        this.keyTypes = keyTypes;
    }

    public Set<String> getProfiles() {
        return profiles;
    }

    public void setProfiles(Set<String> profiles) {
        this.profiles = profiles;
    }

    public Set<Short> getTokenTypes() {
        return tokenTypes;
    }

    public void setTokenTypes(Set<Short> tokenTypes) {
        this.tokenTypes = tokenTypes;
    }

    public Set<COSEparams> getCose() {
        return cose;
    }

    public void setCose(Set<COSEparams> cose) {
        this.cose = cose;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    private byte[] hexStringToByteArray(String str) throws AceException {
        String s = str.replace("0x", "");
        try {
            Integer.parseInt(s, 16);
        }
        catch(NumberFormatException nfe)
        {
            throw new AceException("Hexadecimal value is not valid:\n > " + str);
        }

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private OneKey generateKey(byte[] key) throws CoseException {
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key));

        return new OneKey(keyData);
    }
}
