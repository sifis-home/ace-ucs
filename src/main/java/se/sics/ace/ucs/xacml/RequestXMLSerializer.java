package se.sics.ace.ucs.xacml;

import java.io.StringWriter;
import java.util.logging.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.att.research.xacml.api.Attribute;
import com.att.research.xacml.api.AttributeValue;
import com.att.research.xacml.api.Request;
import com.att.research.xacml.api.RequestAttributes;
import com.att.research.xacml.api.RequestDefaults;
import com.att.research.xacml.std.dom.DOMRequest;
import com.att.research.xacml.std.dom.DOMStructureException;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributeValueType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.AttributesType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.ObjectFactory;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RequestDefaultsType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.RequestType;

public class RequestXMLSerializer {

	private static final Logger LOGGER = Logger.getLogger(RequestXMLSerializer.class.getName());

	public String serialize(Request request) {
		return toXML(toRequestType(request));
	}

	public Request unserialize(String request) {
		try {
			return DOMRequest.load(request);
		} catch (DOMStructureException e) {
			LOGGER.severe(e.getClass().getSimpleName() + " : " + e.getMessage());
			return null;
		}
	}

	public RequestType toRequestType(Request xacmlReq) {
		ObjectFactory objFact = new ObjectFactory();
		RequestType req = new RequestType();
		for (RequestAttributes attrs : xacmlReq.getRequestAttributes()) {
			AttributesType type = objFact.createAttributesType();
			type.setCategory(attrs.getCategory().stringValue());
			for (Attribute attr : attrs.getAttributes()) {
				AttributeType attrtype = objFact.createAttributeType();
				attrtype.setAttributeId(attr.getAttributeId().stringValue());
				attrtype.setIncludeInResult(attr.getIncludeInResults());
				attrtype.setIssuer(attr.getIssuer());
				for (AttributeValue<?> attributeValueType : attr.getValues()) {
					AttributeValueType atValType = objFact.createAttributeValueType();
					atValType.setDataType(attributeValueType.getDataTypeId().stringValue());
					atValType.getContent().add(attributeValueType.getValue());
					attrtype.getAttributeValue().add(atValType);
				}
				type.getAttribute().add(attrtype);
			}
			req.getAttributes().add(type);
		}
		req.setCombinedDecision(xacmlReq.getCombinedDecision());
		RequestDefaults reqDefs = xacmlReq.getRequestDefaults();
		if (reqDefs != null) {
			RequestDefaultsType reqDef = objFact.createRequestDefaultsType();
			reqDef.setXPathVersion(reqDefs.getXPathVersion().toString());
			req.setRequestDefaults(reqDef);
		}
		req.setReturnPolicyIdList(xacmlReq.getReturnPolicyIdList());
		return req;
	}

	public String toXML(RequestType req) {
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(new Class[] { RequestType.class });
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.setProperty("jaxb.formatted.output", false);
			JAXBElement<RequestType> element = new ObjectFactory().createRequest(req);
			element.setValue(req);
			StringWriter stw = new StringWriter();
			marshaller.marshal(element, stw);
			return stw.toString();
		} catch (JAXBException e) {
			LOGGER.severe(e.getClass().getSimpleName() + " : " + e.getMessage());
		}
		return null;
	}

}
