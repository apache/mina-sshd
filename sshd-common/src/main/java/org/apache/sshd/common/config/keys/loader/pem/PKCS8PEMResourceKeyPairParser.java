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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PKCS8PEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {
    // Not exactly according to standard but good enough
    public static final String BEGIN_MARKER = "BEGIN PRIVATE KEY";
    public static final List<String> BEGINNERS =
        Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END PRIVATE KEY";
    public static final List<String> ENDERS =
        Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final String PKCS8_FORMAT = "PKCS#8";

    public static final PKCS8PEMResourceKeyPairParser INSTANCE = new PKCS8PEMResourceKeyPairParser();

    public PKCS8PEMResourceKeyPairParser() {
        super(PKCS8_FORMAT, PKCS8_FORMAT, BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream)
                throws IOException, GeneralSecurityException {
        // Save the data before getting the algorithm OID since we will need it
        byte[] encBytes = IoUtils.toByteArray(stream);
        List<Integer> oidAlgorithm = getPKCS8AlgorithmIdentifier(encBytes);
        PrivateKey prvKey = decodePEMPrivateKeyPKCS8(oidAlgorithm, encBytes);
        PublicKey pubKey = ValidateUtils.checkNotNull(KeyUtils.recoverPublicKey(prvKey),
                "Failed to recover public key of OID=%s", oidAlgorithm);
        KeyPair kp = new KeyPair(pubKey, prvKey);
        return Collections.singletonList(kp);
    }

    public static PrivateKey decodePEMPrivateKeyPKCS8(List<Integer> oidAlgorithm, byte[] keyBytes)
            throws GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(oidAlgorithm, "No PKCS8 algorithm OID");
        return decodePEMPrivateKeyPKCS8(GenericUtils.join(oidAlgorithm, '.'), keyBytes);
    }

    public static PrivateKey decodePEMPrivateKeyPKCS8(String oid, byte[] keyBytes)
                throws GeneralSecurityException {
        KeyPairPEMResourceParser parser =
            PEMResourceParserUtils.getPEMResourceParserByOid(
                ValidateUtils.checkNotNullAndNotEmpty(oid, "No PKCS8 algorithm OID"));
        if (parser == null) {
            throw new NoSuchAlgorithmException("decodePEMPrivateKeyPKCS8(" + oid + ") unknown algorithm identifier");
        }

        String algorithm = ValidateUtils.checkNotNullAndNotEmpty(parser.getAlgorithm(), "No parser algorithm");
        KeyFactory factory = SecurityUtils.getKeyFactory(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return factory.generatePrivate(keySpec);
    }

    public static List<Integer> getPKCS8AlgorithmIdentifier(byte[] input) throws IOException {
        try (DERParser parser = new DERParser(input)) {
            return getPKCS8AlgorithmIdentifier(parser);
        }
    }

    /**
     * According to the standard:
     * <PRE><CODE>
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
     * </CODE></PRE>
     * @param parser The {@link DERParser} to use
     * @return The PKCS8 algorithm OID
     * @throws IOException If malformed data
     * @see #getPKCS8AlgorithmIdentifier(ASN1Object)
     */
    public static List<Integer> getPKCS8AlgorithmIdentifier(DERParser parser) throws IOException {
        return getPKCS8AlgorithmIdentifier(parser.readObject());
    }

    public static List<Integer> getPKCS8AlgorithmIdentifier(ASN1Object privateKeyInfo) throws IOException {
        try (DERParser parser = privateKeyInfo.createParser()) {
            // Skip version
            ASN1Object versionObject = parser.readObject();
            if (versionObject == null) {
                throw new StreamCorruptedException("No version");
            }

            ASN1Object privateKeyAlgorithm = parser.readObject();
            if (privateKeyAlgorithm == null) {
                throw new StreamCorruptedException("No private key algorithm");
            }

            try (DERParser oidParser = privateKeyAlgorithm.createParser()) {
                ASN1Object oid = oidParser.readObject();
                return oid.asOID();
            }
        }
    }
}
