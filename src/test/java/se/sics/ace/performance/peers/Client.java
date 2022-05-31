package se.sics.ace.performance.peers;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import se.sics.ace.AceException;
import se.sics.ace.Constants;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Client {
    private final String name;
    private String defaultScope = null;
    private String defaultAud = null;
    private final List<String> scope;
    private final List<String> aud;

    private final byte[] sId;
    private final byte[] masterSecret;
    private Set<String> keyTypes = new HashSet<String>(){{add("PSK");}};
    private Set<String> profiles = new HashSet<String>(){{add("coap_oscore");}};

    private final OneKey sharedPsk;
    private final OneKey publicKey = null;


    public Client (String name, List<String> scope,
                   List<String> aud, String sId, String masterSecret)
        throws AceException {
        if (name == null || scope == null || aud == null || sId == null || masterSecret == null) {
            throw new AceException("Peer requires non-null parameters");
        }
        this.name = name;
        this.scope = scope;
        this.aud = aud;
        this.sId = hexStringToByteArray(sId);
        this.masterSecret = masterSecret.getBytes(Constants.charset);
        try {
            this.sharedPsk = generateKey(this.masterSecret);
        } catch (CoseException e) {
            throw new RuntimeException(e);
        }
    }

    public String getName() {
        return name;
    }

    public List<String> getScope() {
        return scope;
    }

    public List<String> getAud() {
        return aud;
    }

    public String getDefaultScope() {
        return defaultScope;
    }

    public void setDefaultScope(String defaultScope) {
        this.defaultScope = defaultScope;
    }

    public void setDefaultAud(String defaultAud) {
        this.defaultAud = defaultAud;
    }

    public String getDefaultAud() {
        return defaultAud;
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
