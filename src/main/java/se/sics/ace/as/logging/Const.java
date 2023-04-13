package se.sics.ace.as.logging;

public class Const {

    /**
     * The priority level of the log message
     */
    public static final int PRIO0 = 0;
    public static final int PRIO1 = 1;
    public static final int PRIO2 = 2;
    public static final int PRIO3 = 3;

    /**
     * The severity level of the log message
     */
    public static final int SEV0 = 0;
    public static final int SEV1 = 1;
    public static final int SEV2 = 2;
    public static final int SEV3 = 3;

    /**
     * The category associated with the log message,
     * i.e., the endpoint that generated it.
     */
    public static final String CATEGORY_TOKEN = "ACE AS /token";
    public static final String CATEGORY_TRL = "ACE AS /trl";
    public static final String CATEGORY_INTROSPECT = "ACE AS /introspect";
}
