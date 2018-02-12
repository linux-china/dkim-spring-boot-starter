package org.mvnsearch.boot.dkim;

import info.globalbus.dkim.DKIMSigner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * DKIM email auto configuration
 *
 * @author linux_china
 */
@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)
@EnableConfigurationProperties(DKIMProperties.class)
public class DKIMAutoConfiguration {

    @Bean
    public DKIMSigner dkimSigner(DKIMProperties properties) throws Exception {
        return new DKIMSigner(properties.getSigningDomain(), properties.getSelector(), properties.getPrivateKey());
    }

    @Bean
    public JavaMailSenderAspect javaMailSenderAspect() {
        return new JavaMailSenderAspect();
    }

}