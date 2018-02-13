/*
 * Copyright 2008 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * A licence was granted to the ASF by Florian Sager on 30 November 2008
 */

package info.globalbus.dkim;

import com.sun.mail.util.QPEncoderStream;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * DKIM util
 *
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 * @author linux_china
 */
public class DKIMUtil {

    protected static String[] splitHeader(String header) throws DKIMSignerException {
        int colonPos = header.indexOf(':');
        if (colonPos == -1) {
            throw new DKIMSignerException("The header string " + header + " is no valid RFC 822 header-line");
        }
        return new String[]{header.substring(0, colonPos), header.substring(colonPos + 1)};
    }

    protected static String concatArray(List<String> list, String separator) {
        return list.stream().collect(Collectors.joining(separator));
    }

    protected static boolean isValidDomain(String domainName) {
        Pattern pattern = Pattern.compile("(.+)\\.(.+)");
        Matcher matcher = pattern.matcher(domainName);
        return matcher.matches();
    }

    public static String defaultIfEmpty(String value, String defaultValue) {
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    // FSTODO: converts to "platforms default encoding" might be wrong ?
    protected static String quotedPrintable(String s) {
        try (ByteArrayOutputStream boas = new ByteArrayOutputStream()) {
            try (QPEncoderStream encodeStream = new QPEncoderStream(boas)) {
                encodeStream.write(s.getBytes());
                String encoded = boas.toString();
                encoded = encoded.replaceAll(";", "=3B");
                encoded = encoded.replaceAll(" ", "=20");
                return encoded;
            }
        } catch (IOException ignore) {
        }

        return null;
    }

    protected static String base64Encode(byte[] bytes) {
        String encoded = Base64.getEncoder().encodeToString(bytes);
        // remove unnecessary line feeds after 76 characters
        encoded = encoded.replace("\n", ""); // Linux+Win
        return encoded.replace("\r", ""); // Win --> FSTODO: select Encoder
        // without line termination
    }

    protected static byte[] base64Decode(String text) {
        return Base64.getDecoder().decode(text.replaceAll("\\s+", ""));
    }

    public static PublicKey checkDNSForPublicKey(String signingDomain, String selector) throws DKIMSignerException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        String recordName = selector + "._domainkey." + signingDomain;
        String dnsDkimTextValue;
        try {
            DirContext dnsContext = new InitialDirContext(env);
            javax.naming.directory.Attributes attributes = dnsContext.getAttributes(recordName, new String[]{"TXT"});
            javax.naming.directory.Attribute txtRecord = attributes.get("txt");
            if (txtRecord == null) {
                throw new DKIMSignerException("There is no TXT record available for " + recordName);
            }
            // "v=DKIM1; g=*; k=rsa; p=MIGfMA0G ..."
            dnsDkimTextValue = (String) txtRecord.get();
        } catch (NamingException ne) {
            throw new DKIMSignerException("Selector lookup failed", ne);
        }
        if (dnsDkimTextValue == null) {
            throw new DKIMSignerException("Value of RR " + recordName + " couldn't be retrieved");
        }
        // try to read public key from RR
        String[] tags = dnsDkimTextValue.split(";");
        for (String tag : tags) {
            tag = tag.trim();
            if (tag.startsWith("p=")) {
                try {
                    String publicKeyText = tag.substring(2);
                    return generateX509EncodedPublicKey(publicKeyText);
                } catch (NoSuchAlgorithmException nsae) {
                    throw new DKIMSignerException("RSA algorithm not found by JVM");
                } catch (InvalidKeySpecException ikse) {
                    throw new DKIMSignerException("The public key " + tag + " in RR " + recordName
                            + " couldn't be decoded.");
                }
                // FSTODO: create test signature with private Key and test
                // validation with pubKey to check on a valid key pair
            }
        }
        throw new DKIMSignerException("No public key available in " + recordName);
    }

    /**
     * generate private key with pkcs8 encoded
     *
     * @param raw raw content
     * @return private key
     * @throws NoSuchAlgorithmException Algorithm exception
     * @throws InvalidKeySpecException  invalid key spec exception
     */
    public static PrivateKey generatePrivateKey(byte[] raw) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // decode private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(raw);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * generate private key with pkcs8 encoded
     *
     * @param raw raw content
     * @return public key
     * @throws NoSuchAlgorithmException Algorithm exception
     * @throws InvalidKeySpecException  invalid key spec exception
     */
    public static PublicKey generatePublicKey(byte[] raw) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // decode private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(raw);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * generate public key with X509 encoded
     *
     * @param publicKeyText public key text
     * @return public key
     * @throws NoSuchAlgorithmException Algorithm exception
     * @throws InvalidKeySpecException  invalid key spec exception
     */
    public static PublicKey generateX509EncodedPublicKey(String publicKeyText) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] lines = publicKeyText.split("\n");
        String rawKey = Stream.of(lines).filter(line -> !line.startsWith("---")).collect(Collectors.joining(""));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64Decode(rawKey));
        return keyFactory.generatePublic(keySpec);
    }


}
