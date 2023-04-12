package se.sics.ace.as.logging;

public class RequestPostTopicUUID {

	private OutValue value;
	private String topic_name;
	private String topic_uuid;

	public RequestPostTopicUUID() {

	}

	public void setValue(OutValue value) {
		this.value = value;
	}

	public OutValue getValue() {
		return value;
	}

	public String getTopicName() {
		return topic_name;
	}

	public void setTopicName(String topicName) {
		this.topic_name = topicName;
	}

	public String getTopicUuid() {
		return topic_uuid;
	}

	public void setTopicUuid(String topicUuid) {
		this.topic_uuid = topicUuid;
	}
}
