package se.sics.ace.coap;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * Implements the retrieval of the access token as defined in section 4.1. of 
 * draft-gerdes-ace-dtls-authorize.
 * 
 * TODO: Implement this.
 * 
 * @author Ludwig Seitz
 *
 */
public class DTLSProfilePskStore implements PskStore {

    @Override
    public byte[] getKey(String identity) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        // TODO Auto-generated method stub
        return null;
    }

}
