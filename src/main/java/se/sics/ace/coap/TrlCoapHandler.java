package se.sics.ace.coap;

import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;

import java.util.logging.Logger;

import se.sics.ace.AceException;
import se.sics.ace.TrlStore;
import se.sics.ace.coap.client.TrlResponses;
import se.sics.ace.rs.TokenRepository;


public class TrlCoapHandler implements CoapHandler {

    private static final Logger LOGGER =
            Logger.getLogger(TrlCoapHandler.class.getName());

    private final TrlStore trlStore;

    public TrlCoapHandler(TrlStore trlStore) {
        this.trlStore = trlStore;
    }

    @Override
    public final void onLoad(CoapResponse response) {
        try {
            TrlResponses.processResponse(response, trlStore);
        } catch (AceException error) {
            LOGGER.severe("Assert:" + error);
        }
        LOGGER.info("NOTIFICATION: " + response.advanced());
    }

    @Override
    public final void onError() {
        LOGGER.info("TrlCoapHandler Error: observe failed.");
    }


}
