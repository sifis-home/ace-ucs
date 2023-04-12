package se.sics.ace.as.logging;

public class JsonOut {

	private RequestPostTopicUUID RequestPostTopicUUID;

	public JsonOut() {

	}

	public void setPayload(RequestPostTopicUUID requestPostTopicUUIDIn) {
		this.RequestPostTopicUUID = requestPostTopicUUIDIn;
	}

	public RequestPostTopicUUID getPayload() {
		return RequestPostTopicUUID;
	}

}
