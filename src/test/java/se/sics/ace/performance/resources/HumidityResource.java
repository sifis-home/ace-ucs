package se.sics.ace.performance.resources;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class HumidityResource extends CoapResource {

    String humStr = "57%";

    public HumidityResource() {
        // set resource identifier
        super("humidity");
        // set display name
        getAttributes().setTitle("Humidity Resource");
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        // respond to the request
        exchange.respond(humStr);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();

        humStr = CBORObject.DecodeFromBytes(exchange.getRequestPayload()).AsString();
        System.out.println(getAttributes().getTitle() + ": humidity changed to "
                + humStr + " as requested by client.");

        exchange.respond(CoAP.ResponseCode.CHANGED,
                "Humidity successfully changed to " + humStr);
    }
}
