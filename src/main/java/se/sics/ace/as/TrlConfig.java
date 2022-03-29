package se.sics.ace.as;

/**
 * Class containing the properties related to the /trl endpoint
 *
 * @author Marco Rasori
 */
public class TrlConfig {

    /**
     * The name of the trl endpoint. This will be used for the trl address
     */
    private String name;

    /**
     * The maximum size of the Trl portion of a peer. Once the portion reaches this size,
     * the oldest Trl update will be removed to make room for the latest, which is added.
     */
    private int nMax;

    /**
     * maximum number of diff entries that the AS can include in a diff query response.
     * It can be null if the AS does not pose limits
     */
    private Integer maxBatchSize;

    /**
     * true if the trl uses a RevocationHandler to manage the revocations
     */
    private boolean useRevocationHandler;

    public TrlConfig() {
        this.name = "trl";
        this.nMax = 10;
        this.maxBatchSize = null;
        this.useRevocationHandler = false;
    }

    public TrlConfig(String name, int nMax, Integer maxBatchSize, boolean useRevocationHandler) {
        this.name = name;
        this.nMax = nMax;
        this.maxBatchSize = maxBatchSize;
        this.useRevocationHandler = useRevocationHandler;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getnMax() {
        return nMax;
    }

    public void setnMax(int nMax) {
        this.nMax = nMax;
    }

    public Integer getMaxBatchSize() {
        return maxBatchSize;
    }

    public void setMaxBatchSize(Integer maxBatchSize) {
        this.maxBatchSize = maxBatchSize;
    }

    public boolean isUseRevocationHandler() {
        return useRevocationHandler;
    }

    public void setUseRevocationHandler(boolean useRevocationHandler) {
        this.useRevocationHandler = useRevocationHandler;
    }
}
