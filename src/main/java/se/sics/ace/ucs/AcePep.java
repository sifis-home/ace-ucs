package se.sics.ace.ucs;

import it.cnr.iit.ucs.message.Message;
import it.cnr.iit.ucs.message.reevaluation.ReevaluationResponseMessage;
import it.cnr.iit.ucs.pdp.PDPEvaluation;
import it.cnr.iit.ucs.pep.PEPInterface;
import it.cnr.iit.ucs.properties.components.PepProperties;
import it.cnr.iit.utility.errorhandling.Reject;
import se.sics.ace.AceException;
import se.sics.ace.logging.PerformanceLogger;

import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marco Rasori
 *
 */
public class AcePep implements PEPInterface {

    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(AcePep.class.getName());

    private PepProperties properties;
    private UcsHelper uh;

    public AcePep( PepProperties properties ) {
        Reject.ifNull( properties );
        this.properties = properties;
    }

    @Override
    public String receiveResponse(Message message) {
        return "xxx";
    }

    @Override
    //@Async
    public Message onGoingEvaluation(ReevaluationResponseMessage message) {
        Reject.ifNull(message);
        LOGGER.log(Level.INFO, "OnGoingEvaluation at PEP " +
                "for session {0} ", message.getSessionId());
        try {
            PerformanceLogger.getInstance().getLogger().log(Level.FINE,
                    "t2R          : " + new Date().getTime() + "\n");
        } catch (AssertionError e) {
            LOGGER.finest("Unable to record performance. PerformanceLogger not initialized");
        }

        PDPEvaluation evaluation = message.getEvaluation();
        Reject.ifNull(evaluation);

        if (properties.getRevokeType().equals("HARD")) {
            // tell the UCS that this session has to be ended (with an endAccess)
            try {
                uh.revoke(message.getSessionId());
            } catch (AceException e) {
                LOGGER.severe("Revocation failed: "
                        + e.getMessage());
            }
        }

        return message;

        // +----------------------NOTES----------------------+
        // If revocation type is HARD, tell the UcsHelper that
        // this session has to be terminated with an
        // endAccess.
        // UcsHelper finds all the sessions associated with
        // the same cti as this session.
        // For all the sessions, the UcsHelper will call the
        // endAccess method.
        // Then, it invokes the revoke method of the
        // RevocationHandler to perform the token revocation
        // procedure.
        // +-------------------------------------------------+

    }

    public void setUcsHelper(UcsHelper uh) {
        this.uh = uh;
    }
}
