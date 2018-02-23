package org.mvnsearch.boot.dkim.demo;

import info.globalbus.dkim.DKIMSigner;
import info.globalbus.dkim.DKIMUtil;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.subethamail.wiser.WiserMessage;

import javax.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("test")
public class MailDemoApplicationTests {
    @Autowired
    private JavaMailSender javaMailSender;
    @Autowired
    private WiserServerMock wiserServer;
    @Autowired
    private DKIMSigner dkimSigner;

    @Test
    public void testSendAndVerify() throws Exception {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name());
        helper.setTo("web-wax4z@mail-tester.com");
        helper.setFrom("support@microservices.club");
        helper.setSubject("microservice club with dkim");
        String text = IOUtils.toString(this.getClass().getResource("/email_template/demo.txt"), "utf-8");
        String html = IOUtils.toString(this.getClass().getResource("/email_template/demo.html"), "utf-8");
        helper.setText(text, html);
        mimeMessage.saveChanges();
        javaMailSender.send(mimeMessage);
        verify();
    }

    public void verify() throws Exception {
        Assert.assertTrue(!wiserServer.getMessages().isEmpty());
        WiserMessage wiserMessage = wiserServer.getMessages().get(0);
        MimeMessage receivedMessage = wiserMessage.getMimeMessage();
        Assert.assertNotNull(receivedMessage.getHeader("DKIM-Signature"));
        String publicKeyText = IOUtils.toString(this.getClass().getResourceAsStream("/rsa/demo.public.key.txt"), "utf-8");
        Assert.assertTrue(dkimSigner.verify(receivedMessage, DKIMUtil.generateX509EncodedPublicKey(publicKeyText)));
    }


}
