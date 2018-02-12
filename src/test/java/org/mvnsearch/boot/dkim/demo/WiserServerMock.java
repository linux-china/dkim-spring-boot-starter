package org.mvnsearch.boot.dkim.demo;

import org.springframework.stereotype.Service;
import org.subethamail.wiser.Wiser;
import org.subethamail.wiser.WiserMessage;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.List;

/**
 * wiser server mock
 *
 * @author linux_china
 */
@Service
public class WiserServerMock {

    private Wiser wiser;

    @PostConstruct
    public void start() {
        wiser = new Wiser();
        wiser.setHostname("MailCatcher");
        wiser.setPort(1025);
        wiser.start();

    }

    @PreDestroy
    public void stop() {
        wiser.stop();
    }

    public List<WiserMessage> getMessages() {
        return wiser.getMessages();
    }

}
