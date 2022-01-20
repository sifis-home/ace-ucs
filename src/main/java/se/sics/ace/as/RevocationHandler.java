package se.sics.ace.as;

import org.eclipse.californium.core.observe.ObserveRelationFilter;
import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.coap.as.AceObservableEndpoint;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marco Rasori
 *
 */
public class RevocationHandler {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(RevocationHandler.class.getName());

    /**
     * The database connector for storing and retrieving stuff.
     */
    private DBConnector db;

    private AceObservableEndpoint trl = null;

    private TimeProvider time;

    private Map<String, String> peerIdentitiesToNames = null;

    public RevocationHandler(DBConnector db,
                             TimeProvider time,
                             Map<String, String> peerIdentitiesToNames,
                             AceObservableEndpoint trl)
                                throws AceException {
        if (db == null) {
            LOGGER.severe("RevocationHandler's DBConnector was null");
            throw new AceException(
                    "RevocationHandler's DBConnector must be non-null");
        }
        if (time == null) {
            LOGGER.severe("RevocationHandler's TimeProvider was null");
            throw new AceException("RevocationHandler's TimeProvider "
                    + "must be non-null");
        }

        this.db = db;
        this.time = time;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
        this.trl = trl;
    }

    public void revoke(String cti) throws AceException {

        // get token expiration time (exp)
        long delay = getTimeToExpire(cti);

        // put the token in the trlTable
        db.addRevokedToken(cti);

        // schedule a task to run at time exp-now, that:
        //   - if /trl is present, calls the changed(filter) to notify peers
        //   - removes the token from trlTable
        Timer timer = new Timer();
        timer.schedule(new ExpirationTask(cti), delay);

        // if /trl is present, calls the changed(filter) to notify peers
        if (trl != null) {
            Set<String> peerIds = db.getPertainingPeers(cti);
            ObserveRelationFilter filter = new PertainingPeersFilter(peerIds, peerIdentitiesToNames);
            trl.changed(filter);
        }


        // +----------------------NOTES----------------------+
        // The UCS must have a reference to this component.
        // Indeed, the UCS should call this component when
        // a policy is not satisfied anymore.
        // When a policy is not satisfied anymore, the
        // UCS gets notified by the PEP, which specifies the
        // sessionId.
        // The UCS then retrieves the cti and invokes the
        // endAccess method for all the sessions associated
        // with that cti.
        // At this point, the UCS calls the revoke method of
        // the RevocationHandler.
        // +-------------------------------------------------+

    }


    private long getTimeToExpire(String cti) throws AceException {
        long exp = 0L;
        try {
            exp = this.db.getExpirationTime(cti);
        } catch(AceException e) {
            LOGGER.severe("Error getting token expiration time"
                    + e.getMessage());
            throw new AceException(e.getMessage());
        }
        if (exp == 0L) { // expiration time not found in the db
            LOGGER.log(Level.INFO, "Expiration time not found for token: ", cti);
            throw new AceException("Expiration time not found for token");
        }
        long now = this.time.getCurrentTime();

        long delay = exp - now;
        if (delay < 0) {
            // Trying to revoke an already expired token
            // This might happen since /token and /introspect
            // purge expired tokens in a lazy fashion.
            // Don't know whether I should send a notification anyway
            LOGGER.log(Level.INFO, "The token to be revoked is already expired");

            // However, since at least one expired token exists,
            // we purge expired tokens from the database
            try {
                this.db.purgeExpiredTokens(this.time.getCurrentTime());
            } catch (AceException e) {
                LOGGER.severe("Database error: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
            LOGGER.log(Level.INFO, "Expired tokens purged from the database");
        }
        return delay;
    }


    public class ExpirationTask extends TimerTask {

        private final String cti;

        public ExpirationTask(String cti) {
            this.cti = cti;
        }

        @Override
        public void run() {

            // expire actions:
            // - if /trl is present, get the pertaining peers
            // - remove token from trlTable and from tokenHashTable
            // - if /trl is present, notify pertaining peers

            LOGGER.info("Revoked token expired. " +
                    "Trying to remove it from the trl and notify the peers (if enabled)..." );

            Set<String> peerIds = new HashSet<>();
            if (trl != null) {
                try {
                    peerIds = db.getPertainingPeers(cti);
                } catch (AceException e) {
                    LOGGER.severe("Error getting peers identities: "
                            + e.getMessage());
                }
            }

            try {
                db.deleteExpiredToken(cti);
                db.deleteTokenHash(cti);
            } catch (AceException e) {
                LOGGER.severe("Error deleting expired token: "
                        + e.getMessage());
                return;
            }

            if (trl != null) {
                PertainingPeersFilter filter = new PertainingPeersFilter(peerIds, peerIdentitiesToNames);
                trl.changed(filter); // notify observers
            }

            LOGGER.info("Successfully handled revoked token expiration");
        }
    }
}
