package se.sics.ace.performance.resources;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class BrightnessResource extends CoapResource {

    String briStr = "70%";

    public BrightnessResource() {
        // set resource identifier
        super("brightness");
        // set display name
        getAttributes().setTitle("Brightness Resource");
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        // respond to the request
        exchange.respond(briStr);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();

        briStr = CBORObject.DecodeFromBytes(exchange.getRequestPayload()).AsString();
        System.out.println(getAttributes().getTitle() + ": brightness changed to "
                + briStr + " as requested by client.");

        exchange.respond(CoAP.ResponseCode.CHANGED,
                "Brightness successfully changed to " + briStr);
    }
}
