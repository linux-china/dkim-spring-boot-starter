package org.mvnsearch.boot.dkim;

import info.globalbus.dkim.DKIMSigner;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.core.io.Resource;

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
    public DKIMSigner dkimSigner(DKIMProperties properties, ApplicationContext applicationContext) throws Exception {
        Resource resource = applicationContext.getResource(properties.getPrivateKey());
        byte[] rawKey = IOUtils.toByteArray(resource.getInputStream());
        return new DKIMSigner(properties.getSigningDomain(), properties.getSelector(), rawKey);
    }

    @Bean
    public JavaMailSenderAspect javaMailSenderAspect() {
        return new JavaMailSenderAspect();
    }

}