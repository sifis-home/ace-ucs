package se.sics.ace.performance.resources;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class TempResource extends CoapResource {

    String tempStr = "19.0 C";

    public TempResource() {
        // set resource identifier
        super("temp");
        // set display name
        getAttributes().setTitle("Temp Resource");
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        // respond to the request
        exchange.respond(tempStr);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        exchange.accept();

        tempStr = CBORObject.DecodeFromBytes(exchange.getRequestPayload()).AsString();
        System.out.println(getAttributes().getTitle() + ": temperature changed to "
                + tempStr + " as requested by client.");

        exchange.respond(CoAP.ResponseCode.CHANGED,
                "Temperature successfully changed to " + tempStr);
    }
}
