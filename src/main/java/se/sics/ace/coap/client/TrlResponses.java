package se.sics.ace.coap.client;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.CoapResponse;
import se.sics.ace.AceException;
import se.sics.ace.Constants;

import java.util.Map;
import java.util.logging.Logger;

public class TrlResponses {
    /**
     * The logger
     */
    private static final Logger LOGGER
            = Logger.getLogger(TrlResponses.class.getName());

    /**
     * Different options for handling the response at the TrlStore
     */
    public enum Mode {FULL_QUERY, DIFF_QUERY};

    /**
     * Check the response payload and process the response at the specified TrlStore.
     *
     * @param response the response obtained from the trl endpoint
     * @param trlStore the TrlStore object that uses the response payload to update the local trl structures
     * @param mode the mode to use for processing the response
     * @throws AceException if the response cannot be processed at the TrlStore
     */
    public static void processResponse(CoapResponse response, TrlStore trlStore, Mode mode)
        throws AceException {

        CBORObject payload;
        try {
            payload = checkAndGetPayload(response);
        } catch (AceException e) {
            throw new AceException(e.getMessage());
        }

        switch(mode) {
            case FULL_QUERY:
                trlStore.processFullQuery(payload);
                break;
            case DIFF_QUERY:
                trlStore.processDiffQuery(payload);
                break;
        }
    }


    /**
     * Check payload structure and returns it.
     * If the payload contains an error code, it throws an exception.
     *
     * @param response the response obtained from the trl endpoint
     * @return the response payload
     * @throws AceException if the payload cannot be processed by the TrlStore
     */
    public static CBORObject checkAndGetPayload(CoapResponse response)
            throws AceException {

        byte[] rawPayload = response.getPayload();
        if (rawPayload == null) {
            LOGGER.severe("Received response with null payload");
            throw new AceException("Processing response aborted: null payload");
        }
        CBORObject payload;
        if (response.getOptions().getContentFormat() == Constants.APPLICATION_ACE_CBOR) {
            // response should contain a CBOR array
            payload = CBORObject.DecodeFromBytes(rawPayload);
            if (payload.getType() != CBORType.Array) {
                throw new AceException("Wrong payload type. Expected a CBOR Array");
            }
        }
        else if (response.getOptions().getContentFormat() == Constants.APPLICATION_ACE_TRL_CBOR) {
            // response should contain a CBOR map
            payload = CBORObject.DecodeFromBytes(rawPayload);
            if (payload.getType() != CBORType.Map) {
                throw new AceException("Wrong payload type. Expected a CBOR Map");
            }
            if(!response.isSuccess()) {
                // extract map parameters
                Map<Short, CBORObject> map = Constants.getParams(payload);
                if (map.containsKey(Constants.TRL_ERROR_DESCRIPTION)) {
                        LOGGER.severe("Processing response aborted: "
                                + map.get(Constants.TRL_ERROR_DESCRIPTION));
                    }
                    throw new AceException("Processing response aborted: " +
                            "response contains an error");
            }
        }
        else {
            LOGGER.severe("Received response with unknown content-type");
            throw new AceException("Processing response aborted: unknown content-type");
        }
        return payload;
    }

    /**
     * Extract the CBOR map from an error response from the trl
     *
     * @param response the response obtained from the trl endpoint
     * @return the CBOR map containing the error code, and optionally other fields,
     *         e.g., the error description, included in the response by the trl endpoint at the AS
     * @throws AceException if the response cannot be parsed
     */
    public static Map<Short, CBORObject> getErrorMap(CoapResponse response) throws AceException {

        if (response.isSuccess()) {
            throw new AceException("Response does not contain an error: response was successful");
        }
        CBORObject payload;

        if (response.getOptions().getContentFormat() != Constants.APPLICATION_ACE_TRL_CBOR) {
            throw new AceException("Wrong content-type: expected /application/ace-trl+cbor");
        }
        // response should contain a CBOR map
        payload = CBORObject.DecodeFromBytes(response.getPayload());
        if (payload.getType() != CBORType.Map) {
            throw new AceException("Wrong payload type. Expected a CBOR Map");
        }
        // extract map parameters
        Map<Short, CBORObject> map = Constants.getParams(payload);
        if (!map.containsKey(Constants.TRL_ERROR)) {
            LOGGER.severe("Processing response aborted: payload is missing the error code.");
            throw new AceException("Processing response aborted: payload is missing the error code.");
        }
        return map;
    }
}
