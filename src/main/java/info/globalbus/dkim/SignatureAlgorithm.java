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

/**
 * Allowed signature algorithms by DKIM RFC 4871 with translation to different Java notations
 *
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */
public class SignatureAlgorithm {
    public static SignatureAlgorithm SHA256withRSA = new SignatureAlgorithm("rsa-sha256", "SHA256withRSA", "sha-256");
    public static SignatureAlgorithm SHA1withRSA = new SignatureAlgorithm("rsa-sha1", "SHA1withRSA", "sha-1");

    private String rfc4871Notation;
    private String javaSecNotation;
    private String javaHashNotation;

    /**
     * signing algorithm
     *
     * @param rfc4871Notation  RFC 4871 format
     * @param javaSecNotation  java representation
     * @param javaHashNotation java hashing digest
     */
    public SignatureAlgorithm(String rfc4871Notation, String javaSecNotation, String javaHashNotation) {
        this.rfc4871Notation = rfc4871Notation;
        this.javaSecNotation = javaSecNotation;
        this.javaHashNotation = javaHashNotation;
    }

    public String getJavaHashNotation() {
        return this.javaHashNotation;
    }

    public String getJavaSecNotation() {
        return this.javaSecNotation;
    }

    public String getRfc4871Notation() {
        return this.rfc4871Notation;
    }

    public static SignatureAlgorithm getSignatureAlgorithm(String signatureName) {
        switch (signatureName) {
            case "SHA256withRSA":
            case "rsa-sha256":
                return SHA256withRSA;
            case "SHA1withRSA":
            case "rsa-sha1":
                return SHA1withRSA;
            default:
                return null;
        }
    }
}
