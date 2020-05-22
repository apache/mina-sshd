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
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
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
 * @see    <a href="https://tools.ietf.org/html/rfc3279#section-2.3.2">RFC-3279 section 2.3.2</a>
 */
public class DSSPEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {
    // Not exactly according to standard but good enough
    public static final String BEGIN_MARKER = "BEGIN DSA PRIVATE KEY";
    public static final List<String> BEGINNERS = Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END DSA PRIVATE KEY";
    public static final List<String> ENDERS = Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final String DSS_OID = "1.2.840.10040.4.1";

    public static final DSSPEMResourceKeyPairParser INSTANCE = new DSSPEMResourceKeyPairParser();

    public DSSPEMResourceKeyPairParser() {
        super(KeyUtils.DSS_ALGORITHM, DSS_OID, BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        KeyPair kp = decodeDSSKeyPair(SecurityUtils.getKeyFactory(KeyUtils.DSS_ALGORITHM), stream, false);
        return Collections.singletonList(kp);
    }

    /**
     * <p>
     * The ASN.1 syntax for the private key:
     * </P>
     *
     * <pre>
     * <code>
     * DSAPrivateKey ::= SEQUENCE {
     *      version Version,
     *      p       INTEGER,
     *      q       INTEGER,
     *      g       INTEGER,
     *      y       INTEGER,
     *      x       INTEGER
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
    public static KeyPair decodeDSSKeyPair(KeyFactory kf, InputStream s, boolean okToClose)
            throws IOException, GeneralSecurityException {
        ASN1Object sequence;
        try (DERParser parser = new DERParser(NoCloseInputStream.resolveInputStream(s, okToClose))) {
            sequence = parser.readObject();
        }

        if (!ASN1Type.SEQUENCE.equals(sequence.getObjType())) {
            throw new IOException("Invalid DER: not a sequence: " + sequence.getObjType());
        }

        // Parse inside the sequence
        try (DERParser parser = sequence.createParser()) {
            // Skip version
            ASN1Object version = parser.readObject();
            if (version == null) {
                throw new StreamCorruptedException("No version");
            }

            BigInteger p = parser.readObject().asInteger();
            BigInteger q = parser.readObject().asInteger();
            BigInteger g = parser.readObject().asInteger();
            BigInteger y = parser.readObject().asInteger();
            BigInteger x = parser.readObject().asInteger();
            PublicKey pubKey = kf.generatePublic(new DSAPublicKeySpec(y, p, q, g));
            PrivateKey prvKey = kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
            return new KeyPair(pubKey, prvKey);
        }
    }
}
