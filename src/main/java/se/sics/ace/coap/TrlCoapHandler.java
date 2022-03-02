package se.sics.ace.coap;


import java.util.ArrayList;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;

import java.util.List;
import java.util.logging.Logger;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.rs.TokenRepository;


public class TrlCoapHandler implements CoapHandler {

    private static final Logger LOGGER =
            Logger.getLogger(TrlCoapHandler.class.getName());

    @Override
    public final void onLoad(CoapResponse response) {
        synchronized (this) {
            try {
                assertLoad(response);
            } catch (AceException error) {
                LOGGER.severe("Assert:" + error);
            }
            notifyAll();
        }
        LOGGER.info("Received notification: " + response.advanced());
    }

    /**
     * Check the response and update the localTrl
     *
     * @param response received response
     */
    protected void assertLoad(CoapResponse response) throws AceException {

        if (response.getOptions().getContentFormat() == Constants.APPLICATION_ACE_CBOR) {

            CBORObject payload = CBORObject.DecodeFromBytes(response.getPayload());

            if (payload.getType() != CBORType.Array) {
                throw new AceException("Wrong payload type. Expected a CBOR Array");
            }

            try {
                TokenRepository.getInstance().getTrlManager().updateLocalTrl(payload);
            } catch (AceException e) {
                LOGGER.severe("Cannot update localTrl: " + e.getMessage());
            }

            prettyPrintReceivedTokenHashes(payload);
        }

        else { //assume text/plain
            String content = response.getResponseText();
            System.out.println("NOTIFICATION: " + content);
        }
    }

    private void prettyPrintReceivedTokenHashes(CBORObject payload) {
        List<String> hashes = new ArrayList<>();
        for (int i = 0; i < payload.size(); i++) {
            byte[] tokenHashB = payload.get(i).GetByteString();
            String tokenHashS = new String(tokenHashB, Constants.charset);
            hashes.add(tokenHashS);
        }
        LOGGER.info("List of received token hashes: " + hashes);
    }

    @Override
    public final void onError() {
        LOGGER.info("TrlCoapHandler: Error");
    }


}
