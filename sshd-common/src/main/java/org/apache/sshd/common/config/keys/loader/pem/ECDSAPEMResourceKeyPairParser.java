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
 * @see    <a href="https://tools.ietf.org/html/rfc5915">RFC 5915</a>
 */
public class ECDSAPEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {
    public static final String BEGIN_MARKER = "BEGIN EC PRIVATE KEY";
    public static final List<String> BEGINNERS = Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END EC PRIVATE KEY";
    public static final List<String> ENDERS = Collections.unmodifiableList(Collections.singletonList(END_MARKER));

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
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {

        KeyPair kp = parseECKeyPair(stream, false);
        return Collections.singletonList(kp);
    }

    public static KeyPair parseECKeyPair(
            InputStream inputStream, boolean okToClose)
            throws IOException, GeneralSecurityException {
        try (DERParser parser = new DERParser(NoCloseInputStream.resolveInputStream(inputStream, okToClose))) {
            return parseECKeyPair(null, parser);
        }
    }

    /**
     * @param  curve                    The {@link ECCurves curve} represented by this data (in case it was optional and
     *                                  somehow known externally) if {@code null} then it is assumed to be part of the
     *                                  parsed data. then it is assumed to be part of the data.
     * @param  parser                   The {@link DERParser} for the data
     * @return                          The parsed {@link KeyPair}
     * @throws IOException              If failed to parse the data
     * @throws GeneralSecurityException If failed to generate the keys
     */
    public static KeyPair parseECKeyPair(ECCurves curve, DERParser parser)
            throws IOException, GeneralSecurityException {
        ASN1Object sequence = parser.readObject();
        Map.Entry<ECPublicKeySpec, ECPrivateKeySpec> spec = decodeECPrivateKeySpec(curve, sequence);
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(spec.getKey());
        ECPrivateKey prvKey = (ECPrivateKey) kf.generatePrivate(spec.getValue());
        return new KeyPair(pubKey, prvKey);
    }

    /**
     * <P>
     * ASN.1 syntax according to <A HREF="https://tools.ietf.org/html/rfc5915">RFC 5915</A> is:
     * </P>
     * </BR>
     *
     * <PRE>
     * <CODE>
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     * }
     * </CODE>
     * </PRE>
     * <P>
     * <I>ECParameters</I> syntax according to RFC5480:
     * </P>
     * </BR>
     *
     * <PRE>
     * <CODE>
     * ECParameters ::= CHOICE {
     *      namedCurve         OBJECT IDENTIFIER
     *      -- implicitCurve   NULL
     *      -- specifiedCurve  SpecifiedECDomain
     * }
     * </CODE>
     * </PRE>
     *
     * @param  curve       The {@link ECCurves curve} represented by this data (in case it was optional and somehow
     *                     known externally) if {@code null} then it is assumed to be part of the parsed data.
     * @param  sequence    The {@link ASN1Object} sequence containing the DER encoded data
     * @return             The decoded {@link SimpleImmutableEntry} of {@link ECPublicKeySpec} and
     *                     {@link ECPrivateKeySpec}
     * @throws IOException If failed to to decode the DER stream
     */
    public static Map.Entry<ECPublicKeySpec, ECPrivateKeySpec> decodeECPrivateKeySpec(ECCurves curve, ASN1Object sequence)
            throws IOException {
        ASN1Type objType = (sequence == null) ? null : sequence.getObjType();
        if (!ASN1Type.SEQUENCE.equals(objType)) {
            throw new IOException("Invalid DER: not a sequence: " + objType);
        }

        try (DERParser parser = sequence.createParser()) {
            Map.Entry<ECPrivateKeySpec, ASN1Object> result = decodeECPrivateKeySpec(curve, parser);
            ECPrivateKeySpec prvSpec = result.getKey();
            ASN1Object publicData = result.getValue();
            ECPoint w = (publicData == null) ? decodeECPublicKeyValue(parser) : decodeECPointData(publicData);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, prvSpec.getParams());
            return new SimpleImmutableEntry<>(pubSpec, prvSpec);
        }
    }

    /*
     * According to https://tools.ietf.org/html/rfc5915 - section 3
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey [1] BIT STRING OPTIONAL
     * }
     */
    public static Map.Entry<ECPrivateKeySpec, ASN1Object> decodeECPrivateKeySpec(ECCurves curve, DERParser parser)
            throws IOException {
        // see openssl asn1parse -inform PEM -in ...file... -dump
        ASN1Object versionObject = parser.readObject();
        if (versionObject == null) {
            throw new StreamCorruptedException("No version");
        }

        /*
         * According to https://tools.ietf.org/html/rfc5915 - section 3
         *
         * For this version of the document, it SHALL be set to ecPrivkeyVer1,
         * which is of type INTEGER and whose value is one (1)
         */
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

        /*
         * According to https://tools.ietf.org/html/rfc5915 - section 3
         *
         * parameters specifies the elliptic curve domain parameters associated to the private key. The type
         * ECParameters is discussed in [RFC5480]. As specified in [RFC5480], only the namedCurve CHOICE is permitted.
         * namedCurve is an object identifier that fully identifies the required values for a particular set of elliptic
         * curve domain parameters. Though the ASN.1 indicates that the parameters field is OPTIONAL, implementations
         * that conform to this document MUST always include the parameters field.
         */
        Map.Entry<ECCurves, ASN1Object> result = parseCurveParameter(parser);
        ECCurves namedParam = (result == null) ? null : result.getKey();
        if (namedParam == null) {
            if (curve == null) {
                throw new StreamCorruptedException("Cannot determine curve type");
            }
        } else if (curve == null) {
            curve = namedParam;
        } else if (namedParam != curve) {
            throw new StreamCorruptedException("Mismatched provide (" + curve + ") vs. parsed curve (" + namedParam + ")");
        }

        BigInteger s = ECCurves.octetStringToInteger(keyObject.getPureValueBytes());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, curve.getParameters());
        return new SimpleImmutableEntry<>(keySpec, (result == null) ? null : result.getValue());
    }

    public static Map.Entry<ECCurves, ASN1Object> parseCurveParameter(DERParser parser) throws IOException {
        return parseCurveParameter(parser.readObject());
    }

    public static Map.Entry<ECCurves, ASN1Object> parseCurveParameter(ASN1Object paramsObject) throws IOException {
        if (paramsObject == null) {
            return null;
        }

        ASN1Type objType = paramsObject.getObjType();
        if (objType == ASN1Type.NULL) {
            return null;
        }

        List<Integer> curveOID;
        try (DERParser paramsParser = paramsObject.createParser()) {
            ASN1Object namedCurve = paramsParser.readObject();
            if (namedCurve == null) {
                throw new StreamCorruptedException("Missing named curve parameter");
            }

            /*
             * The curve OID is OPTIONAL - if it is not there then the
             * public key data replaces it
             */
            objType = namedCurve.getObjType();
            if (objType == ASN1Type.BIT_STRING) {
                return new SimpleImmutableEntry<>(null, namedCurve);
            }

            curveOID = namedCurve.asOID();
        }

        ECCurves curve = ECCurves.fromOIDValue(curveOID);
        if (curve == null) {
            throw new StreamCorruptedException("Unknown curve OID: " + curveOID);
        }

        return new SimpleImmutableEntry<>(curve, null);
    }

    /**
     * <P>
     * ASN.1 syntax according to rfc5915 is:
     * </P>
     * </BR>
     *
     * <pre>
     * <code>
     *      publicKey  [1] BIT STRING OPTIONAL
     * </code>
     * </pre>
     *
     * @param  parser      The {@link DERParser} assumed to be positioned at the start of the data
     * @return             The encoded {@link ECPoint}
     * @throws IOException If failed to create the point
     */
    public static final ECPoint decodeECPublicKeyValue(DERParser parser) throws IOException {
        return decodeECPublicKeyValue(parser.readObject());
    }

    public static final ECPoint decodeECPublicKeyValue(ASN1Object dataObject) throws IOException {
        // see openssl asn1parse -inform PEM -in ...file... -dump
        if (dataObject == null) {
            throw new StreamCorruptedException("No public key data bytes");
        }

        /*
         * According to https://tools.ietf.org/html/rfc5915
         *
         * Though the ASN.1 indicates publicKey is OPTIONAL, implementations
         * that conform to this document SHOULD always include the publicKey field
         */
        try (DERParser dataParser = dataObject.createParser()) {
            return decodeECPointData(dataParser.readObject());
        }
    }

    public static final ECPoint decodeECPointData(ASN1Object pointData) throws IOException {
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
