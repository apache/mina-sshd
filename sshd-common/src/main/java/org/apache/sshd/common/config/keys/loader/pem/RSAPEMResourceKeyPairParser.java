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
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc3279#section-2.3.1">RFC-3279 section 2.3.1</a>
 */
public class RSAPEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {
    // Not exactly according to standard but good enough
    public static final String BEGIN_MARKER = "BEGIN RSA PRIVATE KEY";
    public static final List<String> BEGINNERS = Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END RSA PRIVATE KEY";
    public static final List<String> ENDERS = Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final String RSA_OID = "1.2.840.113549.1.1.1";

    public static final RSAPEMResourceKeyPairParser INSTANCE = new RSAPEMResourceKeyPairParser();

    public RSAPEMResourceKeyPairParser() {
        super(KeyUtils.RSA_ALGORITHM, RSA_OID, BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        KeyPair kp = decodeRSAKeyPair(SecurityUtils.getKeyFactory(KeyUtils.RSA_ALGORITHM), stream, false);
        return Collections.singletonList(kp);
    }

    /**
     * <p>
     * The ASN.1 syntax for the private key as per RFC-3447 section A.1.2:
     * </P>
     *
     * <pre>
     * <code>
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version,
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1)
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
     * }
     * </code>
     * </pre>
     *
     * @param  kf                       The {@link KeyFactory} To use to generate the keys
     * @param  s                        The {@link InputStream} containing the encoded bytes
     * @param  okToClose                <code>true</code> if the method may close the input stream regardless of success
     *                                  or failure
     * @return                          The recovered {@link KeyPair}
     * @throws IOException              If failed to read or decode the bytes
     * @throws GeneralSecurityException If failed to generate the keys
     */
    public static KeyPair decodeRSAKeyPair(KeyFactory kf, InputStream s, boolean okToClose)
            throws IOException, GeneralSecurityException {
        ASN1Object sequence;
        try (DERParser parser = new DERParser(NoCloseInputStream.resolveInputStream(s, okToClose))) {
            sequence = parser.readObject();
        }

        if (!ASN1Type.SEQUENCE.equals(sequence.getObjType())) {
            throw new IOException("Invalid DER: not a sequence: " + sequence.getObjType());
        }

        try (DERParser parser = sequence.createParser()) {
            // Skip version
            ASN1Object versionObject = parser.readObject();
            if (versionObject == null) {
                throw new StreamCorruptedException("No version");
            }

            // as per RFC-3447 section A.1.2
            BigInteger version = versionObject.asInteger();
            if (!BigInteger.ZERO.equals(version)) {
                throw new StreamCorruptedException("Multi-primes N/A");
            }

            BigInteger modulus = parser.readObject().asInteger();
            BigInteger publicExp = parser.readObject().asInteger();
            PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(modulus, publicExp));

            BigInteger privateExp = parser.readObject().asInteger();
            BigInteger primeP = parser.readObject().asInteger();
            BigInteger primeQ = parser.readObject().asInteger();
            BigInteger primeExponentP = parser.readObject().asInteger();
            BigInteger primeExponentQ = parser.readObject().asInteger();
            BigInteger crtCoef = parser.readObject().asInteger();
            RSAPrivateKeySpec prvSpec = new RSAPrivateCrtKeySpec(
                    modulus, publicExp, privateExp, primeP, primeQ, primeExponentP, primeExponentQ, crtCoef);
            PrivateKey prvKey = kf.generatePrivate(prvSpec);
            return new KeyPair(pubKey, prvKey);
        }
    }
}
