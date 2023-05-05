package se.sics.ace.as;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.observe.ObserveRelationFilter;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.logging.DhtLogger;
import se.sics.ace.as.logging.Const;
import se.sics.ace.coap.as.AceObservableEndpoint;
import se.sics.ace.ucs.UcsHelper;

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

    private PDP pdp = null;

    private Map<String, DiffSet> DiffSetsMap;

    public RevocationHandler(DBConnector db,
                             PDP pdp,
                             TimeProvider time,
                             Map<String, String> peerIdentitiesToNames,
                             Map<String, DiffSet> DiffSetsMap,
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

        this.pdp = pdp;
        this.db = db;
        this.time = time;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
        this.DiffSetsMap = DiffSetsMap;
        this.trl = trl;
    }

    public void revoke(String cti) throws AceException {

        // Get token expiration time (exp)
        long delay;
        try {
            delay = getTimeToExpire(cti);
        } catch (AceException e) {
            LOGGER.log(Level.INFO, "Revocation aborted: (getting token expiration time)");
            DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                    "Revocation aborted: (getting token expiration time)");
            throw e;
        }

        // The token to be revoked was already expired
        if (delay < 0){
            LOGGER.log(Level.INFO, "The token to revoke was already expired");
            DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                    "Revocation aborted: The token to revoke was already expired");
            return;
        }


        // Put the token in the trlTable
        db.addRevokedToken(cti);

        // Put the token hash in each DiffSet of the pertaining peers
        Set<String> peerIds = db.getPertainingPeers(cti);
        try {
            addRevokedTokenHashToDiffSets(cti, peerIds);
        } catch (AceException e) {
            LOGGER.log(Level.INFO, "Revocation aborted: (adding diff entry)");
            DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                    "Revocation aborted: (adding diff entry)");
            throw e;
        }

        // Schedule a task to run at time exp-now, that:
        //   - if /trl is present, calls the changed(filter) to notify peers
        //   - removes the token from trlTable
        Timer timer = new Timer();
        timer.schedule(new ExpirationTask(cti), delay);

        // Notify observing pertaining peers
        if (trl != null) {
            ObserveRelationFilter filter = new PertainingPeersFilter(peerIds, peerIdentitiesToNames);
            trl.changed(filter);
        }

        LOGGER.log(Level.INFO, "Token revoked: " + cti);
        DhtLogger.sendLog(Const.TYPE_INFO, Const.PRIO_LOW, Const.CAT_STATUS, Const.DEVICE_NAME,
                "Token revoked. "
                        + "[ctiStr: " + cti + ". "
                        + "pertainingPeers: " + peerIds + "]");

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

    private void addRevokedTokenHashToDiffSets(String cti, Set<String> peerIds) throws AceException {
        String tokenHash = db.getTokenHashMap().get(cti);

        CBORObject added = CBORObject.NewArray();
        added.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));

        for (String id : peerIds) {
            try {
                DiffSetsMap.get(id).pushDiffEntry(CBORObject.NewArray(), added);
            } catch (AceException e) {
                LOGGER.severe("Error adding a diff entry " +
                        "to the DiffSet object: " + e.getMessage());
            }
        }
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
            LOGGER.log(Level.INFO, "The token to be revoked is already expired");

            // However, since at least one expired token exists,
            // we purge expired tokens from the database
            try {
                Set<String> ctis = db.getExpiredTokens(now);
                if (this.pdp instanceof UcsHelper) {
                    for (String i : ctis)
                        this.pdp.removeSessions4Cti(i);
                }
                for (String i : ctis) {
                    this.db.deleteTokenHash(i);
                }
                this.db.purgeExpiredTokens(now);
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

        /**
         * Trigger when a revoked token expires.
         * It performs the following operations:
         * - Get the pertaining peers
         * - Update pertaining peers' DiffSets structures
         * - Remove the expired token from trlTable and from tokenHashTable
         * - Notify observing pertaining peers
         */
        @Override
        public void run() {

            LOGGER.info("Revoked token expired. " +
                    "Trying to remove it from the trl and notify the peers (if enabled)..." );

            //1. Get the pertaining peers
            Set<String> peerIds = new HashSet<>();

            try {
                peerIds = db.getPertainingPeers(cti);
            } catch (AceException e) {
                LOGGER.severe("Token removal from trl aborted: "
                        + "(getting peers identities from db) "
                        + e.getMessage());
                DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                        "Token removal from trl aborted: (getting peers identities from db)");
                return;
            }


            //2. Update pertaining peers' DiffSets structures
            String tokenHash = null;
            try {
                tokenHash = db.getTokenHashMap().get(cti);
            } catch (AceException e) {
                LOGGER.severe("Token removal from trl aborted:" +
                        "(getting token hash from db) "
                        + e.getMessage());
                DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                        "Token removal from trl aborted: (getting token hash from db)");
                return;
            }
            if (tokenHash == null) {
                LOGGER.severe("Error deleting token: Token hash not found.");
                return;
            }
            CBORObject removed = CBORObject.NewArray();
            removed.Add(CBORObject.FromObject(tokenHash.getBytes(Constants.charset)));

            for (String id : peerIds) {
                try {
                    DiffSetsMap.get(id).pushDiffEntry(removed, CBORObject.NewArray());
                } catch (AceException e) {
                    LOGGER.severe("Error adding a diff entry " +
                            "to the DiffSet object: " + e.getMessage());
                    DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                            "Error adding a diff entry to the DiffSet object");
                }
            }


            //3. Remove the expired token from trlTable and from tokenHashTable
            try {
                db.deleteExpiredToken(cti);
                db.deleteTokenHash(cti);
            } catch (AceException e) {
                LOGGER.severe("Error deleting expired token: "
                        + e.getMessage());
                DhtLogger.sendLog(Const.TYPE_ERROR, Const.PRIO_HIGH, Const.CAT_STATUS, Const.DEVICE_NAME,
                        "Token removal from trl aborted: (deleting token hash from db)");
                return;
            }


            //4. Notify observing pertaining peers
            if (trl != null) {
                PertainingPeersFilter filter = new PertainingPeersFilter(peerIds, peerIdentitiesToNames);
                trl.changed(filter); // notify observers
            }

            LOGGER.info("Token removal from the trl completed: " + cti);
            DhtLogger.sendLog(Const.TYPE_INFO, Const.PRIO_LOW, Const.CAT_STATUS, Const.DEVICE_NAME,
                    "Token removal from the trl completed. "
                            + "[ctiStr: " + cti + ". "
                            + "pertainingPeers: " + peerIds + "]");
        }
    }
}
