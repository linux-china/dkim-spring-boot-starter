dkim-spring-boot-starter
========================
DKIM support for spring-boot-starter-mail.

# Why DKIM?

Avoid your sent email in spam folder.

# How it works

*  DKIMSigner to sign MimeMessage
*  AOP @Before to interceptor JavaMailSender.send and sign MimeMessage before sending

### How to use

* Add :

````xml
<dependency>
    <groupId>org.mvnsearch.boot</groupId>
    <artifactId>dkim-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
````

* in application.properties, add following configuration
```
dkim.signing-domain=demo.com
dkim.selector=default
dkim.privateKey=classpath:/rsa/demo.private.key.der
```
* User JavamailSender as usual because of AOP

# How to generate DKIM key

a DKIM key setup:

There are test keys in the keys/ directory but be aware to use those only for your tests.

You need:

a) a private key on your hard disc (e.g. in keys/); you can generate a new key by

     openssl genrsa -out private.key.pem

DKIM for JavaMail needs the private key in DER format, you can transform a PEM key with openssl:

     openssl pkcs8 -topk8 -nocrypt -in private.key.pem -out private.key.der -outform der

b) a public key in your DNS; here is a sample ressource record with selector "default": default._domainkey IN TXT "v=DKIM1; g=*; k=rsa; p=MIG...the_public_key_here...AQAB" (see http://www.ietf.org/rfc/rfc4871.txt for details)

You can use openssl to get a public key from the private key:

      openssl rsa -inform PEM -in private.key.pem -pubout

# Reference

* Mail Tester: https://www.mail-tester.com/
* DKIM: http://www.dkim.org/
* 28 Tips To Avoid Spam Filters When Doing Email Marketing: https://monk.webengage.com/how-to-avoid-spam-filters-when-sending-emails/
* DKIM for Java: https://github.com/globalbus/dkim
