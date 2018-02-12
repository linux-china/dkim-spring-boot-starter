package org.mvnsearch.boot.dkim;

import info.globalbus.dkim.DKIMSigner;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.mail.internet.MimeMessage;

/**
 * javamail sender aspect for AOP
 *
 * @author linux_china
 */
@Aspect()
@Component
public class JavaMailSenderAspect {
    @Autowired
    private DKIMSigner dkimSigner;

    @Before("execution(* org.springframework.mail.javamail.JavaMailSender.send(javax.mail.internet.MimeMessage)) && args(mimeMessage)")
    public void doBefore(JoinPoint joinPoint, MimeMessage mimeMessage) throws Throwable {
        mimeMessage.saveChanges();
        dkimSigner.sign(mimeMessage);
    }

}
