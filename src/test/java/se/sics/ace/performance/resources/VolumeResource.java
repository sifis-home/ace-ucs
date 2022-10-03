package se.sics.ace.performance.resources;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class VolumeResource extends CoapResource {

    String volStr = "30%";

    public VolumeResource() {
        // set resource identifier
        super("volume");
        // set display name
        getAttributes().setTitle("Volume Resource");
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        // respond to the request
        exchange.respond(volStr);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();

        volStr = CBORObject.DecodeFromBytes(exchange.getRequestPayload()).AsString();
        System.out.println(getAttributes().getTitle() + ": volume changed to "
                + volStr + " as requested by client.");

        exchange.respond(CoAP.ResponseCode.CHANGED,
                "Volume successfully changed to " + volStr);
    }
}
