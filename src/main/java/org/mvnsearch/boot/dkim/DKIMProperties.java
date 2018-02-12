package org.mvnsearch.boot.dkim;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * dkim properties
 *
 * @author linux_china
 */
@ConfigurationProperties(prefix = "dkim")
public class DKIMProperties {
    /**
     * signing domain
     */
    private String signingDomain;
    /**
     * selector
     */
    private String selector = "default";
    /**
     * private key, end with .der
     */
    private String privateKey;

    public String getSigningDomain() {
        return signingDomain;
    }

    public void setSigningDomain(String signingDomain) {
        this.signingDomain = signingDomain;
    }

    public String getSelector() {
        return selector;
    }

    public void setSelector(String selector) {
        this.selector = selector;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
