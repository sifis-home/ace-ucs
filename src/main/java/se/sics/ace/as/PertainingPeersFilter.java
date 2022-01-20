package se.sics.ace.as;

import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.observe.ObserveRelationFilter;
import se.sics.ace.AceException;
import se.sics.ace.coap.CoapReq;

import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 *
 * @author Marco Rasori
 *
 */
public class PertainingPeersFilter implements ObserveRelationFilter {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(PertainingPeersFilter.class.getName());

    /**
     * The set of identities that have to be notified
     */
    public Set<String> ids;

    /**
     * Map with (i) key: the OSCORE identity of the Client or Resource Server, and
     * (ii) value: the name of that peer with the AS.
     * It can be null if DTLS profile is used
     */
    Map<String, String> peerIdentitiesToNames;

    public PertainingPeersFilter(Set<String> ids, Map<String, String> peerIdentitiesToNames) {
        this.ids = ids;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
    }

    @Override
    public boolean accept(ObserveRelation relation) {

        String relationId = "";
        try {
            CoapReq req = CoapReq.getInstance(relation.getExchange().getRequest());
            relationId = req.getSenderId();
        } catch (AceException e) {
            LOGGER.info(e.getMessage());
            return false;
        }

        if (peerIdentitiesToNames != null)
            return ids.contains(peerIdentitiesToNames.get(relationId));
        else
            return ids.contains(relationId);
    }
}
