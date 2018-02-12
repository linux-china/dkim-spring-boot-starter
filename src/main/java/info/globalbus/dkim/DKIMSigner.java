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

import com.sun.mail.util.CRLFOutputStream;
import org.apache.commons.io.IOUtils;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeUtility;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.Map.Entry;

/**
 * Main class providing a signature according to DKIM RFC 4871.
 *
 * @author Florian Sager, http://www.agitos.de, 15.10.2008
 */
public class DKIMSigner {

    /**
     * DKIM Signature SMTP header
     */
    private static String DKIM_SIGNATURE_HEADER = "DKIM-Signature";
    /**
     * max header length
     */
    private static int MAX_HEADER_LENGTH = 67;

    private static ArrayList<String> MINIMUM_HEADERS_TO_SIGN = new ArrayList<String>();

    static {
        MINIMUM_HEADERS_TO_SIGN.add("From");
        MINIMUM_HEADERS_TO_SIGN.add("To");
        MINIMUM_HEADERS_TO_SIGN.add("Subject");
    }

    private String[] defaultHeadersToSign = new String[]{"From", "To", "Subject", "Message-ID"};
    //too much
    private String[] defaultHeadersToSign2 = new String[]{"Content-Description", "Content-ID", "Content-Type",
            "Content-Transfer-Encoding", "Cc", "Date", "From", "In-Reply-To", "List-Subscribe", "List-Post",
            "List-Owner", "List-Id", "List-Archive", "List-Help", "List-Unsubscribe", "MIME-Version", "Message-ID",
            "Resent-Sender", "Resent-Cc", "Resent-Date", "Resent-To", "Reply-To", "References", "Resent-Message-ID",
            "Resent-From", "Sender", "Subject", "To"};

    // use rsa-sha256 by default, see RFC 4871
    private SigningAlgorithm signingAlgorithm = SigningAlgorithm.SHA256withRSA;
    private Signature signatureService;
    private MessageDigest messageDigest;
    private String signingDomain;
    private String selector;
    private String identity;
    private boolean lengthParam = true;
    private boolean zParam = false;
    private Canonicalization headerCanonicalization = Canonicalization.RELAXED;
    private Canonicalization bodyCanonicalization = Canonicalization.RELAXED;
    private PrivateKey privateKey;

    public DKIMSigner(String signingDomain, String selector, PrivateKey privateKey) throws Exception {
        initDKIMSigner(signingDomain, selector, privateKey);
    }

    public DKIMSigner(String signingDomain, String selector, byte[] raw) throws Exception {
        initDKIMSigner(signingDomain, selector, generatePrivateKey(raw));
    }

    public DKIMSigner(String signingDomain, String selector, String privateKeyFileName) throws Exception {
        byte[] raw = IOUtils.toByteArray(new FileInputStream(privateKeyFileName));
        initDKIMSigner(signingDomain, selector, generatePrivateKey(raw));
    }

    public PrivateKey generatePrivateKey(byte[] raw) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // decode private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(raw);
        return keyFactory.generatePrivate(keySpec);
    }

    private void initDKIMSigner(String signingDomain, String selector, PrivateKey privateKey) throws DKIMSignerException {
        if (!DKIMUtil.isValidDomain(signingDomain)) {
            throw new DKIMSignerException(signingDomain + " is an invalid signing domain");
        }
        this.signingDomain = signingDomain;
        this.selector = selector.trim();
        this.privateKey = privateKey;
        this.setSigningAlgorithm(this.signingAlgorithm);
        this.setIdentity("@" + signingDomain);
    }

    public void setIdentity(String identity) throws DKIMSignerException {
        this.identity = identity;
        if (identity != null) {
            identity = identity.trim();
            if (!identity.endsWith("@" + this.signingDomain) && !identity.endsWith("." + this.signingDomain)) {
                throw new DKIMSignerException("The domain part of " + identity + " has to be " + this.signingDomain + " or its subdomain");
            }
        }
    }

    public String getIdentity() {
        return this.identity;
    }

    public Canonicalization getBodyCanonicalization() {
        return this.bodyCanonicalization;
    }

    public void setBodyCanonicalization(Canonicalization bodyCanonicalization) {
        this.bodyCanonicalization = bodyCanonicalization;
    }

    public Canonicalization getHeaderCanonicalization() {
        return this.headerCanonicalization;
    }

    public void setHeaderCanonicalization(Canonicalization headerCanonicalization) {
        this.headerCanonicalization = headerCanonicalization;
    }

    public String[] getDefaultHeadersToSign() {
        return this.defaultHeadersToSign;
    }

    public void addHeaderToSign(String header) {
        if (header == null || "".equals(header))
            return;
        int len = this.defaultHeadersToSign.length;
        String[] headersToSign = new String[len + 1];
        for (int i = 0; i < len; i++) {
            if (header.equals(this.defaultHeadersToSign[i])) {
                return;
            }
            headersToSign[i] = this.defaultHeadersToSign[i];
        }
        headersToSign[len] = header;
        this.defaultHeadersToSign = headersToSign;
    }

    public void removeHeaderToSign(String header) {
        if (header == null || "".equals(header))
            return;
        int len = this.defaultHeadersToSign.length;
        if (len == 0)
            return;
        String[] headersToSign = new String[len - 1];
        int found = 0;
        for (int i = 0; i < len - 1; i++) {
            if (header.equals(this.defaultHeadersToSign[i + found])) {
                found = 1;
            }
            headersToSign[i] = this.defaultHeadersToSign[i + found];
        }
        this.defaultHeadersToSign = headersToSign;
    }

    public void setLengthParam(boolean lengthParam) {
        this.lengthParam = lengthParam;
    }

    public boolean getLengthParam() {
        return this.lengthParam;
    }

    public boolean isZParam() {
        return this.zParam;
    }

    public void setZParam(boolean param) {
        this.zParam = param;
    }

    public SigningAlgorithm getSigningAlgorithm() {
        return this.signingAlgorithm;
    }

    public void setSigningAlgorithm(SigningAlgorithm signingAlgorithm) throws DKIMSignerException {
        try {
            this.messageDigest = MessageDigest.getInstance(signingAlgorithm.getJavaHashNotation());
        } catch (NoSuchAlgorithmException nsae) {
            throw new DKIMSignerException("The hashing algorithm " + signingAlgorithm.getJavaHashNotation() + " is not known by the JVM", nsae);
        }
        try {
            this.signatureService = Signature.getInstance(signingAlgorithm.getJavaSecNotation());
        } catch (NoSuchAlgorithmException nsae) {
            throw new DKIMSignerException("The signing algorithm " + signingAlgorithm.getJavaSecNotation() + " is not known by the JVM", nsae);
        }
        try {
            this.signatureService.initSign(this.privateKey);
        } catch (InvalidKeyException ike) {
            throw new DKIMSignerException("The provided private key is invalid", ike);
        }
        this.signingAlgorithm = signingAlgorithm;
    }

    private static String serializeDKIMSignature(Map<String, String> dkimSignature) {
        Set<Entry<String, String>> entries = dkimSignature.entrySet();
        StringBuilder fbuf;
        StringBuilder buf = new StringBuilder();
        int pos = 0;
        for (Entry<String, String> entry : entries) {
            // buf.append(entry.getKey()).append("=").append(entry.getValue()).append(";\t");
            fbuf = new StringBuilder();
            fbuf.append(entry.getKey()).append("=").append(entry.getValue()).append(";");
            if (pos + fbuf.length() + 1 > MAX_HEADER_LENGTH) {
                pos = fbuf.length();
                // line folding : this doesn't work "sometimes" --> maybe
                // someone likes to debug this
                /*
                 * int i = 0; while (i<pos) { if
                 * (fbuf.substring(i).length()>MAXHEADERLENGTH) {
                 * buf.append("\r\n\t").append(fbuf.substring(i,
                 * i+MAXHEADERLENGTH)); i += MAXHEADERLENGTH; } else {
                 * buf.append("\r\n\t").append(fbuf.substring(i)); pos -= i;
                 * break; } }
                 */
                buf.append("\r\n\t").append(fbuf);
            } else {
                buf.append(" ").append(fbuf);
                pos += fbuf.length() + 1;
            }
        }
        buf.append("\r\n\tb=");
        return buf.toString().trim();
    }

    private static String foldSignedSignature(String s, int offset) {
        int i = 0;
        StringBuilder buf = new StringBuilder();
        while (true) {
            if (offset > 0 && s.substring(i).length() > MAX_HEADER_LENGTH - offset) {
                buf.append(s.substring(i, i + MAX_HEADER_LENGTH - offset));
                i += MAX_HEADER_LENGTH - offset;
                offset = 0;
            } else if (s.substring(i).length() > MAX_HEADER_LENGTH) {
                buf.append("\r\n\t").append(s.substring(i, i + MAX_HEADER_LENGTH));
                i += MAX_HEADER_LENGTH;
            } else {
                buf.append("\r\n\t").append(s.substring(i));
                break;
            }
        }
        return buf.toString();
    }

    public String sign(MimeMessage message) throws DKIMSignerException, MessagingException, IOException {
        Map<String, String> dkimSignature = new LinkedHashMap<>();
        dkimSignature.put("v", "1");
        dkimSignature.put("a", this.signingAlgorithm.getRfc4871Notation());
        dkimSignature.put("q", "dns/txt");
        dkimSignature.put("c", getHeaderCanonicalization().getType() + "/" + getBodyCanonicalization().getType());
        dkimSignature.put("t", (new Date().getTime() / 1000) + "");
        dkimSignature.put("s", this.selector);
        dkimSignature.put("d", this.signingDomain);

        // set identity inside signature
        if (this.identity != null) {
            this.setIdentity(this.identity);
            dkimSignature.put("i", DKIMUtil.quotedPrintable(this.identity));
        }

        // process header
        @SuppressWarnings("unchecked")
        ArrayList<String> assureHeaders = (ArrayList<String>) MINIMUM_HEADERS_TO_SIGN.clone();

        // intersect defaultHeadersToSign with available headers
        StringBuilder headerList = new StringBuilder();
        StringBuilder headerContent = new StringBuilder();
        StringBuilder zParamString = new StringBuilder();

        Enumeration<?> headerLines = message.getMatchingHeaderLines(this.defaultHeadersToSign);
        while (headerLines.hasMoreElements()) {
            String header = (String) headerLines.nextElement();
            String[] headerParts = DKIMUtil.splitHeader(header);
            headerList.append(headerParts[0]).append(":");
            headerContent.append(this.headerCanonicalization.canonicalizeHeader(headerParts[0], headerParts[1]))
                    .append("\r\n");
            assureHeaders.remove(headerParts[0]);

            // add optional z= header list, DKIM-Quoted-Printable
            if (this.zParam) {
                zParamString.append(headerParts[0]).append(":")
                        .append(DKIMUtil.quotedPrintable(headerParts[1].trim()).replace("|", "=7C")).append("|");
            }
        }

        if (!assureHeaders.isEmpty()) {
            throw new DKIMSignerException("Could not find the header fields "
                    + DKIMUtil.concatArray(assureHeaders, ", ") + " for signing");
        }

        dkimSignature.put("h", headerList.substring(0, headerList.length() - 1));

        if (this.zParam) {
            String zParamTemp = zParamString.toString();
            dkimSignature.put("z", zParamTemp.substring(0, zParamTemp.length() - 1));
        }

        // process body
        String body = getMessageBodyText(message);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (CRLFOutputStream crlfos = new CRLFOutputStream(baos)) {
            crlfos.write(body.getBytes());
        } catch (IOException e) {
            throw new DKIMSignerException("The body conversion to MIME canonical CRLF line terminator failed", e);
        }
        body = baos.toString();
        body = this.bodyCanonicalization.canonicalizeBody(body);
        if (this.lengthParam) {
            dkimSignature.put("l", body.length() + "");
        }
        // calculate and encode body hash
        dkimSignature.put("bh", DKIMUtil.base64Encode(this.messageDigest.digest(body.getBytes())));
        // create signature
        String serializedSignature = serializeDKIMSignature(dkimSignature);
        synchronized (this) {
            byte[] signedSignature;
            try {
                this.signatureService.update(headerContent
                        .append(this.headerCanonicalization.canonicalizeHeader(DKIM_SIGNATURE_HEADER, " "
                                + serializedSignature)).toString().getBytes());
                signedSignature = this.signatureService.sign();
            } catch (SignatureException se) {
                throw new DKIMSignerException("The signing operation by Java security failed", se);
            }
            message.setHeader(DKIM_SIGNATURE_HEADER, serializedSignature + foldSignedSignature(DKIMUtil.base64Encode(signedSignature), 3));
            return DKIM_SIGNATURE_HEADER + ": " + serializedSignature + foldSignedSignature(DKIMUtil.base64Encode(signedSignature), 3);
        }
    }

    String getMessageBodyText(MimeMessage mimeMessage) throws MessagingException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream osEncoding = MimeUtility.encode(bos, mimeMessage.getEncoding());
        mimeMessage.getDataHandler().writeTo(osEncoding);
        osEncoding.flush();
        return bos.toString();
    }
}