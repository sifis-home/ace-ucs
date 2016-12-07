package se.sics.ace.coap;

import java.net.InetSocketAddress;
import java.sql.SQLException;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

import se.sics.ace.AceException;
import se.sics.ace.as.SQLConnector;

/**
 * A SQLConnector for CoAP, implementing the PskStore interface.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDBConnector extends SQLConnector implements PskStore {

    /**
     * Constructor.
     *  
     * @param dbUrl  the database URL, if null the default will be used
     * @param user   the database user, if null the default will be used
     * @param pwd    the database user's password, if null the default 
     *               will be used
     *
     * @throws SQLException
     */
    public CoapDBConnector(String dbUrl, String user, String pwd)
            throws SQLException {
        super(dbUrl, user, pwd);

    }

    @Override
    public byte[] getKey(String identity) {
        byte[] key = null;
        try {
            key = super.getCPSK(identity);
        } catch (AceException e) {
            return null;
        }
        if (key == null) {
            try {
                key = super.getRsPSK(identity);
            } catch (AceException e) {
                return null;
            }
        }
        return key;
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        return null;
    }

}
