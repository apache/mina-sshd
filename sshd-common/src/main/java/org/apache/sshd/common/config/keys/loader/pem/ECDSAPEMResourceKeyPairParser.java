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
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
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
 */
public class ECDSAPEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {
    public static final String BEGIN_MARKER = "BEGIN EC PRIVATE KEY";
    public static final List<String> BEGINNERS =
        Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END EC PRIVATE KEY";
    public static final List<String> ENDERS =
        Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    /**
     * @see <A HREF="https://tools.ietf.org/html/rfc3279#section-2.3.5">RFC-3279 section 2.3.5</A>
     */
    public static final String ECDSA_OID = "1.2.840.10045.2.1";

    public static final ECDSAPEMResourceKeyPairParser INSTANCE = new ECDSAPEMResourceKeyPairParser();

    public ECDSAPEMResourceKeyPairParser() {
        super(KeyUtils.EC_ALGORITHM, ECDSA_OID, BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream)
                throws IOException, GeneralSecurityException {
        Map.Entry<ECPublicKeySpec, ECPrivateKeySpec> spec = decodeECPrivateKeySpec(stream, false);
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(spec.getKey());
        ECPrivateKey prvKey = (ECPrivateKey) kf.generatePrivate(spec.getValue());
        KeyPair kp = new KeyPair(pubKey, prvKey);
        return Collections.singletonList(kp);
    }

    /**
     * <P>ASN.1 syntax according to rfc5915 is:</P></BR>
     * <PRE><CODE>
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     * }
     * </CODE></PRE>
     * <P><I>ECParameters</I> syntax according to RFC5480:</P></BR>
     * <PRE><CODE>
     * ECParameters ::= CHOICE {
     *      namedCurve         OBJECT IDENTIFIER
     *      -- implicitCurve   NULL
     *      -- specifiedCurve  SpecifiedECDomain
     * }
     * </CODE></PRE>
     * @param inputStream The {@link InputStream} containing the DER encoded data
     * @param okToClose {@code true} if OK to close the DER stream once parsing complete
     * @return The decoded {@link SimpleImmutableEntry} of {@link ECPublicKeySpec} and {@link ECPrivateKeySpec}
     * @throws IOException If failed to to decode the DER stream
     */
    public static SimpleImmutableEntry<ECPublicKeySpec, ECPrivateKeySpec> decodeECPrivateKeySpec(InputStream inputStream, boolean okToClose) throws IOException {
        ASN1Object sequence;
        try (DERParser parser = new DERParser(NoCloseInputStream.resolveInputStream(inputStream, okToClose))) {
            sequence = parser.readObject();
        }

        if (!ASN1Type.SEQUENCE.equals(sequence.getObjType())) {
            throw new IOException("Invalid DER: not a sequence: " + sequence.getObjType());
        }

        // Parse inside the sequence
        try (DERParser parser = sequence.createParser()) {
            ECPrivateKeySpec prvSpec = decodeECPrivateKeySpec(parser);
            ECCurves curve = ECCurves.fromCurveParameters(prvSpec.getParams());
            if (curve == null) {
                throw new StreamCorruptedException("Unknown curve");
            }

            ECPoint w = decodeECPublicKeyValue(curve, parser);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, prvSpec.getParams());
            return new SimpleImmutableEntry<>(pubSpec, prvSpec);
        }
    }

    public static final ECPrivateKeySpec decodeECPrivateKeySpec(DERParser parser) throws IOException {
        // see openssl asn1parse -inform PEM -in ...file... -dump
        ASN1Object versionObject = parser.readObject(); // Skip version
        if (versionObject == null) {
            throw new StreamCorruptedException("No version");
        }

        // as per RFC-5915 section 3
        BigInteger version = versionObject.asInteger();
        if (!BigInteger.ONE.equals(version)) {
            throw new StreamCorruptedException("Bad version value: " + version);
        }

        ASN1Object keyObject = parser.readObject();
        if (keyObject == null) {
            throw new StreamCorruptedException("No private key value");
        }

        ASN1Type objType = keyObject.getObjType();
        if (!ASN1Type.OCTET_STRING.equals(objType)) {
            throw new StreamCorruptedException("Non-matching private key object type: " + objType);
        }

        ASN1Object paramsObject = parser.readObject();
        if (paramsObject == null) {
            throw new StreamCorruptedException("No parameters value");
        }

        // TODO make sure params object tag is 0xA0

        List<Integer> curveOID;
        try (DERParser paramsParser = paramsObject.createParser()) {
            ASN1Object namedCurve = paramsParser.readObject();
            if (namedCurve == null) {
                throw new StreamCorruptedException("Missing named curve parameter");
            }

            curveOID = namedCurve.asOID();
        }

        ECCurves curve = ECCurves.fromOIDValue(curveOID);
        if (curve == null) {
            throw new StreamCorruptedException("Unknown curve OID: " + curveOID);
        }

        BigInteger s = ECCurves.octetStringToInteger(keyObject.getPureValueBytes());
        return new ECPrivateKeySpec(s, curve.getParameters());
    }

    /**
     * <P>ASN.1 syntax according to rfc5915 is:</P></BR>
     * <pre><code>
     *      publicKey  [1] BIT STRING OPTIONAL
     * </code></pre>
     * @param curve The {@link ECCurves} curve
     * @param parser The {@link DERParser} assumed to be positioned at the
     * start of the data
     * @return The encoded {@link ECPoint}
     * @throws IOException If failed to create the point
     */
    public static final ECPoint decodeECPublicKeyValue(ECCurves curve, DERParser parser) throws IOException {
        // see openssl asn1parse -inform PEM -in ...file... -dump
        ASN1Object dataObject = parser.readObject();
        if (dataObject == null) {
            throw new StreamCorruptedException("No public key data bytes");
        }

        try (DERParser dataParser = dataObject.createParser()) {
            ASN1Object pointData = dataParser.readObject();
            if (pointData == null) {
                throw new StreamCorruptedException("Missing public key data parameter");
            }

            ASN1Type objType = pointData.getObjType();
            if (!ASN1Type.BIT_STRING.equals(objType)) {
                throw new StreamCorruptedException("Non-matching public key object type: " + objType);
            }

            // see https://tools.ietf.org/html/rfc5480#section-2.2
            byte[] octets = pointData.getValue();
            return ECCurves.octetStringToEcPoint(octets);
        }
    }

}
