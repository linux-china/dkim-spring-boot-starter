package org.mvnsearch.boot.dkim.demo;

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

    @Test
    public void modification() throws Exception {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name());
        helper.setTo("web-v5zap@mail-tester.com");
        helper.setFrom("support@microservices.club");
        helper.setSubject("microservice club with dkim");
        String text = IOUtils.toString(this.getClass().getResource("/email_template/demo.txt"), "utf-8");
        String html = IOUtils.toString(this.getClass().getResource("/email_template/demo.html"), "utf-8");
        helper.setText(text, html);
        mimeMessage.saveChanges();
        javaMailSender.send(mimeMessage);
        Assert.assertTrue(!wiserServer.getMessages().isEmpty());
        WiserMessage wiserMessage = wiserServer.getMessages().get(0);
        Assert.assertNotNull(wiserMessage.getMimeMessage().getHeader("DKIM-Signature"));
    }


}
