/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.config.keys.loader.pem;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.util.List;

import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;

/**
 * <PRE>
 * <CODE>
 * PrivateKeyInfo ::= SEQUENCE {
 *          version Version,
 *          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *          privateKey PrivateKey,
 *          attributes [0] IMPLICIT Attributes OPTIONAL
 *  }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 * AlgorithmIdentifier ::= SEQUENCE {
 *      algorithm       OBJECT IDENTIFIER,
 *      parameters      ANY DEFINED BY algorithm OPTIONAL
 * }
 * </CODE>
 * </PRE>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc5208#section-5">RFC 5208 - section 5</a>
 */
public class PKCS8PrivateKeyInfo /* TODO Cloneable */ {
    private BigInteger version;
    private List<Integer> algorithmIdentifier;
    private ASN1Object algorithmParameter;
    private ASN1Object privateKeyBytes;

    public PKCS8PrivateKeyInfo() {
        super();
    }

    public PKCS8PrivateKeyInfo(byte[] encBytes) throws IOException {
        decode(encBytes);
    }

    public PKCS8PrivateKeyInfo(DERParser parser) throws IOException {
        this(parser.readObject());
    }

    public PKCS8PrivateKeyInfo(ASN1Object privateKeyInfo) throws IOException {
        decode(privateKeyInfo);
    }

    public BigInteger getVersion() {
        return version;
    }

    public void setVersion(BigInteger version) {
        this.version = version;
    }

    public List<Integer> getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(List<Integer> algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public ASN1Object getAlgorithmParameter() {
        return algorithmParameter;
    }

    public void setAlgorithmParameter(ASN1Object algorithmParameter) {
        this.algorithmParameter = algorithmParameter;
    }

    public ASN1Object getPrivateKeyBytes() {
        return privateKeyBytes;
    }

    public void setPrivateKeyBytes(ASN1Object privateKeyBytes) {
        this.privateKeyBytes = privateKeyBytes;
    }

    public void decode(byte[] encBytes) throws IOException {
        try (DERParser parser = new DERParser(encBytes)) {
            decode(parser);
        }
    }

    public void decode(DERParser parser) throws IOException {
        decode(parser.readObject());
    }

    /**
     * Decodes the current information with the data from the provided encoding. <B>Note:</B> User should
     * {@link #clear()} the current information before parsing
     *
     * @param  privateKeyInfo The {@link ASN1Object} encoding
     * @throws IOException    If failed to parse the encoding
     */
    public void decode(ASN1Object privateKeyInfo) throws IOException {
        /*
         * SEQUENCE {
         *      INTEGER 0x00 (0 decimal)
         *      SEQUENCE {
         *         OBJECTIDENTIFIER encryption type
         *         OBJECTIDENTIFIER extra info - may be NULL
         *      }
         *      OCTETSTRING private key
         * }
         */
        ASN1Type objType = privateKeyInfo.getObjType();
        if (objType != ASN1Type.SEQUENCE) {
            throw new StreamCorruptedException("Not a top level sequence: " + objType);
        }

        try (DERParser parser = privateKeyInfo.createParser()) {
            ASN1Object versionObject = parser.readObject();
            if (versionObject == null) {
                throw new StreamCorruptedException("No version");
            }

            setVersion(versionObject.asInteger());

            ASN1Object privateKeyAlgorithm = parser.readObject();
            if (privateKeyAlgorithm == null) {
                throw new StreamCorruptedException("No private key algorithm");
            }

            objType = privateKeyInfo.getObjType();
            if (objType != ASN1Type.SEQUENCE) {
                throw new StreamCorruptedException("Not an algorithm parameters sequence: " + objType);
            }

            try (DERParser oidParser = privateKeyAlgorithm.createParser()) {
                ASN1Object oid = oidParser.readObject();
                setAlgorithmIdentifier(oid.asOID());

                // Extra information is OPTIONAL
                ASN1Object extraInfo = oidParser.readObject();
                objType = (extraInfo == null) ? ASN1Type.NULL : extraInfo.getObjType();
                if (objType != ASN1Type.NULL) {
                    setAlgorithmParameter(extraInfo);
                }
            }

            ASN1Object privateKeyData = parser.readObject();
            if (privateKeyData == null) {
                throw new StreamCorruptedException("No private key data");
            }

            objType = privateKeyData.getObjType();
            if (objType != ASN1Type.OCTET_STRING) {
                throw new StreamCorruptedException("Private key data not an " + ASN1Type.OCTET_STRING + ": " + objType);
            }

            setPrivateKeyBytes(privateKeyData);
            // TODO add implicit attributes parsing
        }
    }

    public void clear() {
        setVersion(null);
        setAlgorithmIdentifier(null);
        setPrivateKeyBytes(null);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[version=" + getVersion()
               + ", algorithmIdentifier=" + getAlgorithmIdentifier()
               + "]";
    }
}
