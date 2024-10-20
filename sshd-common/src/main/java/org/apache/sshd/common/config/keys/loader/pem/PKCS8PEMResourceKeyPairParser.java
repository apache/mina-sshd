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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.CredentialException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.Decryptor;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc5208">RFC 5208</A>
 */
public class PKCS8PEMResourceKeyPairParser extends AbstractPEMResourceKeyPairParser {

    public static final String BEGIN_MARKER = "BEGIN PRIVATE KEY";
    public static final String BEGIN_ENCRYPTED_MARKER = "BEGIN ENCRYPTED PRIVATE KEY";
    public static final List<String> BEGINNERS = GenericUtils.unmodifiableList(BEGIN_MARKER, BEGIN_ENCRYPTED_MARKER);

    public static final String END_MARKER = "END PRIVATE KEY";
    public static final String END_ENCRYPTED_MARKER = "END ENCRYPTED PRIVATE KEY";
    public static final List<String> ENDERS = GenericUtils.unmodifiableList(END_MARKER, END_ENCRYPTED_MARKER);

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
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] privateBytes = IoUtils.toByteArray(stream);
        if (beginMarker.contains(BEGIN_ENCRYPTED_MARKER)) {
            // RFC 5958 EncryptedPrivateKeyInfo.
            return decryptKeyPairs(session, resourceKey, passwordProvider, privateBytes);
        }
        PKCS8PrivateKeyInfo pkcs8Info = new PKCS8PrivateKeyInfo(privateBytes);
        try {
            return extractKeyPairs(privateBytes, pkcs8Info);
        } finally {
            pkcs8Info.clear();
            Arrays.fill(privateBytes, (byte) 0);
        }
    }

    public Collection<KeyPair> decryptKeyPairs(
            SessionContext session, NamedResource resourceKey,
            FilePasswordProvider passwordProvider, byte[] encrypted)
            throws IOException, GeneralSecurityException {
        if (passwordProvider == null) {
            throw new CredentialException("Missing password provider for encrypted resource=" + resourceKey);
        }
        // This requires Bouncy Castle due to various bugs regarding PBES2 in various Java versions.
        //
        // See https://stackoverflow.com/questions/66286457/load-an-encrypted-pcks8-pem-private-key-in-java
        Decryptor decryptor = SecurityUtils.getBouncycastleEncryptedPrivateKeyInfoDecryptor();

        Collection<KeyPair> keyPairs = passwordProvider.decode(session, resourceKey, password -> {
            char[] key = password.toCharArray();
            try {
                byte[] decrypted = decryptor.decrypt(encrypted, key);
                PKCS8PrivateKeyInfo pkcs8Info = new PKCS8PrivateKeyInfo(decrypted);
                try {
                    return extractKeyPairs(decrypted, pkcs8Info);
                } finally {
                    pkcs8Info.clear();
                    Arrays.fill(decrypted, (byte) 0);
                }
            } finally {
                Arrays.fill(key, (char) 0);
            }
        });
        return keyPairs == null ? Collections.emptyList() : keyPairs;
    }

    public Collection<KeyPair> extractKeyPairs(byte[] encBytes, PKCS8PrivateKeyInfo pkcs8Info)
            throws IOException, GeneralSecurityException {
        List<Integer> oidAlgorithm = pkcs8Info.getAlgorithmIdentifier();
        String oid = GenericUtils.join(oidAlgorithm, '.');
        KeyPair kp;
        if (SecurityUtils.isECCSupported()
                && ECDSAPEMResourceKeyPairParser.ECDSA_OID.equals(oid)) {
            ASN1Object privateKeyBytes = pkcs8Info.getPrivateKeyBytes();
            ASN1Object extraInfo = pkcs8Info.getAlgorithmParameter();
            ASN1Type objType = (extraInfo == null) ? ASN1Type.NULL : extraInfo.getObjType();
            List<Integer> oidCurve = (objType == ASN1Type.NULL) ? Collections.emptyList() : extraInfo.asOID();
            ECCurves curve = null;
            if (GenericUtils.isNotEmpty(oidCurve)) {
                curve = ECCurves.fromOIDValue(oidCurve);
                if (curve == null) {
                    throw new NoSuchAlgorithmException("Cannot match EC curve OID=" + oidCurve);
                }
            }

            try (DERParser parser = privateKeyBytes.createParser()) {
                kp = ECDSAPEMResourceKeyPairParser.parseECKeyPair(curve, parser);
            }
        } else if (SecurityUtils.isEDDSACurveSupported()
                && EdDSASupport.ED25519_OID.endsWith(oid)) {
            ASN1Object privateKeyBytes = pkcs8Info.getPrivateKeyBytes();
            kp = EdDSASupport.decodeEd25519KeyPair(privateKeyBytes.getPureValueBytes());
        } else {
            PrivateKey prvKey = decodePEMPrivateKeyPKCS8(oidAlgorithm, encBytes);
            PublicKey pubKey = ValidateUtils.checkNotNull(KeyUtils.recoverPublicKey(prvKey),
                    "Failed to recover public key of OID=%s", oidAlgorithm);
            kp = new KeyPair(pubKey, prvKey);
        }

        return Collections.singletonList(kp);
    }

    public static PrivateKey decodePEMPrivateKeyPKCS8(List<Integer> oidAlgorithm, byte[] keyBytes)
            throws GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(oidAlgorithm, "No PKCS8 algorithm OID");
        return decodePEMPrivateKeyPKCS8(GenericUtils.join(oidAlgorithm, '.'), keyBytes);
    }

    public static PrivateKey decodePEMPrivateKeyPKCS8(String oid, byte[] keyBytes)
            throws GeneralSecurityException {
        KeyPairPEMResourceParser parser = PEMResourceParserUtils.getPEMResourceParserByOid(
                ValidateUtils.checkNotNullAndNotEmpty(oid, "No PKCS8 algorithm OID"));
        if (parser == null) {
            throw new NoSuchAlgorithmException("decodePEMPrivateKeyPKCS8(" + oid + ") unknown algorithm identifier");
        }

        String algorithm = ValidateUtils.checkNotNullAndNotEmpty(parser.getAlgorithm(), "No parser algorithm");
        KeyFactory factory = SecurityUtils.getKeyFactory(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return factory.generatePrivate(keySpec);
    }
}
