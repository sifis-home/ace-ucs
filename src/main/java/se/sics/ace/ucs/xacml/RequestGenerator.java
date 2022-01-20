package se.sics.ace.ucs.xacml;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.w3c.dom.Node;

import com.att.research.xacml.api.Attribute;
import com.att.research.xacml.api.Identifier;
import com.att.research.xacml.api.Request;
import com.att.research.xacml.api.RequestAttributes;
import com.att.research.xacml.api.RequestReference;
import com.att.research.xacml.api.XACML3;
import com.att.research.xacml.std.IdentifierImpl;
import com.att.research.xacml.std.StdAttribute;
import com.att.research.xacml.std.StdAttributeValue;
import com.att.research.xacml.std.StdRequest;
import com.att.research.xacml.std.StdRequestAttributes;

public class RequestGenerator {
	private static final Logger log = Logger.getLogger(RequestGenerator.class.getName());

	boolean isXACMLv3 = false;

	public Request createXACMLV3Request(String user, String resource, String action, boolean isXACMLv3,
			AdditionalAttribute... attributes) {
		this.isXACMLv3 = isXACMLv3;
		List<AdditionalAttribute> subjectCustomAttributes = new ArrayList<>();
		List<AdditionalAttribute> actionCustomAttributes = new ArrayList<>();
		List<AdditionalAttribute> resourceCustomAttributes = new ArrayList<>();
		List<AdditionalAttribute> environmentCustomAttributes = new ArrayList<>();
		List<AdditionalAttribute> organizationCustomAttributes = new ArrayList<>();
		if (attributes != null) {
			for (AdditionalAttribute additionalAttribute : attributes) {
				if (additionalAttribute.getCategory() == null) {
					continue;
				}

				switch (additionalAttribute.getCategory()) {
				case SUBJECT:
					subjectCustomAttributes.add(additionalAttribute);
					break;
				case ACTION:
					actionCustomAttributes.add(additionalAttribute);
					break;
				case RESOURCE:
					resourceCustomAttributes.add(additionalAttribute);
					break;
				case ENVIRONMENT:
					environmentCustomAttributes.add(additionalAttribute);
					break;
				case ORGANIZATION:
					organizationCustomAttributes.add(additionalAttribute);
					break;
				}
			}
		}

		RequestAttributes actionAttributes = generateActionAttributes(null, action, actionCustomAttributes);
		RequestAttributes subjectAttributes = generateSubjectAttributes(null, user, subjectCustomAttributes);
		RequestAttributes resourceAttributes = generateResourceAttributes(null, resource, resourceCustomAttributes);
		List<RequestAttributes> listRequestAttributes = new ArrayList<>();
		listRequestAttributes.add(actionAttributes);
		listRequestAttributes.add(subjectAttributes);
		listRequestAttributes.add(resourceAttributes);
		List<RequestReference> listRequestReferences = new ArrayList<>();
		boolean returnPolicyIdListIn = false;
		boolean combinedDecisionIn = false;
		StdRequest request = new StdRequest(null, returnPolicyIdListIn, combinedDecisionIn, listRequestAttributes,
				listRequestReferences);
//		LOGGER.info(request::toString);
		return request;
	}

	public Request createXACMLV3Request(String user, String resource, String action, boolean isXACMLv3) {
		this.isXACMLv3 = isXACMLv3;
		RequestAttributes actionAttributes = generateActionAttributes(null, action, null);
		RequestAttributes subjectAttributes = generateSubjectAttributes(null, user, null);
		RequestAttributes resourceAttributes = generateResourceAttributes(null, resource, null);
		ArrayList<RequestAttributes> listRequestAttributes = new ArrayList<>();
		listRequestAttributes.add(actionAttributes);
		listRequestAttributes.add(subjectAttributes);
		listRequestAttributes.add(resourceAttributes);
		ArrayList<RequestReference> listRequestReferences = new ArrayList<>();
		boolean returnPolicyIdListIn = false;
		boolean combinedDecisionIn = false;
		StdRequest request = new StdRequest(null, returnPolicyIdListIn, combinedDecisionIn, listRequestAttributes,
				listRequestReferences);
//		LOGGER.info(request::toString);
		return request;
	}

	private RequestAttributes generateSubjectAttributes(Node nodeContentRoot, String subject,
			List<AdditionalAttribute> subjectCustomAttributes) {
		boolean includeInResultsIn = true;
		StdAttributeValue<String> subjectAttributeValue = new StdAttributeValue<>(XACML3.ID_DATATYPE_STRING, subject);
		StdAttribute subjectAttribute = new StdAttribute(XACML3.ID_SUBJECT_CATEGORY_ACCESS_SUBJECT,
				XACML3.ID_SUBJECT_SUBJECT_ID, subjectAttributeValue, "", includeInResultsIn);
		List<Attribute> listSubjectAttributes = new ArrayList<>();
		listSubjectAttributes.add(subjectAttribute);
		processCustomAttributes(subjectCustomAttributes, includeInResultsIn, listSubjectAttributes,
				XACML3.ID_SUBJECT_CATEGORY_ACCESS_SUBJECT);
		return new StdRequestAttributes(XACML3.ID_SUBJECT_CATEGORY_ACCESS_SUBJECT, listSubjectAttributes,
				nodeContentRoot, null);
	}

	private RequestAttributes generateActionAttributes(Node nodeContentRoot, String action,
			List<AdditionalAttribute> actionCustomAttributes) {
		boolean includeInResultsIn = true;
		StdRequestAttributes actionAttributes = null;
		StdAttributeValue<String> actionAttributeValue = new StdAttributeValue<>(XACML3.ID_DATATYPE_STRING, action);
		if (isXACMLv3) {
			StdAttribute actionAttribute = new StdAttribute(XACML3.ID_ATTRIBUTE_CATEGORY_ACTION,
					XACML3.ID_ACTION_ACTION_ID, actionAttributeValue, "", includeInResultsIn);
			List<Attribute> listActionAttributes = new ArrayList<>();
			listActionAttributes.add(actionAttribute);
			processCustomAttributes(actionCustomAttributes, includeInResultsIn, listActionAttributes,
					XACML3.ID_ATTRIBUTE_CATEGORY_ACTION);
			actionAttributes = new StdRequestAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_ACTION, listActionAttributes,
					nodeContentRoot, null);
		} else {
			IdentifierImpl actionCategoryId = new IdentifierImpl(
					"urn:oasis:names:tc:xacml:1.0:action-category:access-action");
			IdentifierImpl actionAttributeId = new IdentifierImpl("urn:oasis:names:tc:xacml:1.0:action:action-id");
			StdAttribute actionAttribute = new StdAttribute(actionCategoryId, actionAttributeId, actionAttributeValue,
					"", includeInResultsIn);
			List<Attribute> listActionAttributes = new ArrayList<>();
			listActionAttributes.add(actionAttribute);
			processCustomAttributes(actionCustomAttributes, includeInResultsIn, listActionAttributes, actionCategoryId);
			actionAttributes = new StdRequestAttributes(actionCategoryId, listActionAttributes, nodeContentRoot, null);
		}
		return actionAttributes;
	}

	private void processCustomAttributes(List<AdditionalAttribute> customAttributes, boolean includeInResultsIn,
			List<Attribute> listActionAttributes, Identifier category) {
		if (customAttributes == null) {
			return;
		}
		for (AdditionalAttribute additionalAttribute : customAttributes) {
			StdAttributeValue<String> actionCustomAttributeValue = new StdAttributeValue<>(XACML3.ID_DATATYPE_STRING,
					additionalAttribute.getValue());
			StdAttribute actionCustomAttribute = new StdAttribute(category,
					new IdentifierImpl(additionalAttribute.getName()), actionCustomAttributeValue, "",
					includeInResultsIn);
			listActionAttributes.add(actionCustomAttribute);
		}
	}

	private RequestAttributes generateResourceAttributes(Node nodeContentRoot, String resource,
			List<AdditionalAttribute> resourceCustomAttributes) {
		boolean includeInResult = true;
		StdRequestAttributes resourceAttributes = null;
		StdAttributeValue<String> resourceAttributeValue = new StdAttributeValue<>(XACML3.ID_DATATYPE_STRING, resource);
		if (isXACMLv3) {
			StdAttribute resourceAttribute = new StdAttribute(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE,
					XACML3.ID_RESOURCE_RESOURCE_ID, resourceAttributeValue, "", includeInResult);
			List<Attribute> listResourceAttributes = new ArrayList<>();
			listResourceAttributes.add(resourceAttribute);
			processCustomAttributes(resourceCustomAttributes, includeInResult, listResourceAttributes,
					XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE);
			resourceAttributes = new StdRequestAttributes(XACML3.ID_ATTRIBUTE_CATEGORY_RESOURCE, listResourceAttributes,
					nodeContentRoot, null);
		} else {
			IdentifierImpl resCategoryId = new IdentifierImpl(
					"urn:oasis:names:tc:xacml:1.0:resource-category:access-resource");
			IdentifierImpl resAttributeId = new IdentifierImpl("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
			StdAttribute resourceAttribute = new StdAttribute(resCategoryId, resAttributeId, resourceAttributeValue, "",
					includeInResult);
			List<Attribute> listResourceAttributes = new ArrayList<>();
			listResourceAttributes.add(resourceAttribute);
			processCustomAttributes(resourceCustomAttributes, includeInResult, listResourceAttributes, resCategoryId);
			resourceAttributes = new StdRequestAttributes(resCategoryId, listResourceAttributes, nodeContentRoot, null);
		}
		return resourceAttributes;
	}
}
