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

package org.apache.sshd.common.config.keys.loader.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPKeyPairResourceParser extends AbstractKeyPairResourceParser {
    public static final String BEGIN_MARKER = "BEGIN PGP PRIVATE KEY BLOCK";
    public static final List<String> BEGINNERS =
        Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END PGP PRIVATE KEY BLOCK";
    public static final List<String> ENDERS =
        Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final PGPKeyPairResourceParser INSTANCE = new PGPKeyPairResourceParser();

    public PGPKeyPairResourceParser() {
        super(BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, List<String> lines)
                throws IOException, GeneralSecurityException {
        // We need to re-construct the original data - including start/end markers
        String eol = System.lineSeparator();
        int numLines = GenericUtils.size(lines);
        StringBuilder sb = new StringBuilder(
                beginMarker.length() + endMarker.length() + 4 + numLines * 80)
            .append(beginMarker);
        if (numLines > 0) {
            for (String l : lines) {
                sb.append(eol).append(l);
            }
        }
        sb.append(eol).append(endMarker).append(eol);

        String keyData = sb.toString();
        byte[] dataBytes = keyData.getBytes(StandardCharsets.US_ASCII);
        return extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, dataBytes);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, InputStream stream)
                throws IOException, GeneralSecurityException {
        for (int retryCount = 0;; retryCount++) {
            String password = (passwordProvider == null) ? null : passwordProvider.getPassword(resourceKey, retryCount);
            Collection<KeyPair> keys;
            try {
                if (retryCount > 0) {
                    stream.reset();
                }

                Key key = new Key(stream, password);
                if (GenericUtils.isEmpty(password)) {
                    key.setNoPassphrase(true);
                } else {
                    key.setPassphrase(password);
                }

                keys = extractKeyPairs(resourceKey, key.getSubkeys());
            } catch (IOException | GeneralSecurityException | PGPException | RuntimeException e) {
                ResourceDecodeResult result = (passwordProvider != null)
                    ? passwordProvider.handleDecodeAttemptResult(resourceKey, retryCount, password, e)
                    : ResourceDecodeResult.TERMINATE;
                if (result == null) {
                    result = ResourceDecodeResult.TERMINATE;
                }

                switch (result) {
                    case TERMINATE:
                        if (e instanceof PGPException) {
                            throw new StreamCorruptedException(
                                "Failed (" + e.getClass().getSimpleName() + ")"
                                + " to decode " + resourceKey + ": " + e.getMessage());
                        } else if (e instanceof IOException) {
                            throw (IOException) e;
                        } else if (e instanceof GeneralSecurityException) {
                            throw (GeneralSecurityException) e;
                        } else {
                            throw (RuntimeException) e;
                        }
                    case RETRY:
                        continue;
                    case IGNORE:
                        return Collections.emptyList();
                    default:
                        throw new ProtocolException("Unsupported decode attempt result (" + result + ") for " + resourceKey);
                }
            }

            if (passwordProvider != null) {
                passwordProvider.handleDecodeAttemptResult(resourceKey, retryCount, password, null);
            }
            return keys;
        }
    }

    public List<KeyPair> extractKeyPairs(String resourceKey, Collection<? extends Subkey> subKeys)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(subKeys)) {
            return Collections.emptyList();
        }

        List<KeyPair> kpList = new ArrayList<>(subKeys.size());
        boolean debugEnabled = log.isDebugEnabled();
        for (Subkey sk : subKeys) {
            PublicKey pubKey;
            try {
                pubKey = extractPublicKey(resourceKey, sk);
                if (pubKey == null) {
                    if (debugEnabled) {
                        log.debug("extractKeyPairs({}) no public key extracted from {}", resourceKey, sk);
                    }
                    continue;
                }
            } catch (IOException | GeneralSecurityException | RuntimeException | Error e) {
                log.error("extractKeyPairs({}) failed ({}) to extract public key of {}: {}",
                    resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw e;
            }

            PrivateKey prvKey;
            try {
                prvKey = extractPrivateKey(resourceKey, sk, pubKey);
                if (prvKey == null) {
                    if (debugEnabled) {
                        log.debug("extractKeyPairs({}) no private key extracted from {}", resourceKey, sk);
                    }
                    continue;
                }
            } catch (IOException | GeneralSecurityException | RuntimeException | Error e) {
                log.error("extractKeyPairs({}) failed ({}) to extract private key of {}: {}",
                    resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw e;
            } catch (PGPException e) {
                log.error("extractKeyPairs({}) failed ({}) to parse private key of {}: {}",
                    resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw new StreamCorruptedException("Failed to parse " + resourceKey + " sub-key=" + sk + ": " + e.getMessage());
            }

            KeyPair kp = new KeyPair(pubKey, prvKey);
            KeyPair prev = kpList.isEmpty()
                ? null
                : kpList.stream()
                    .filter(e -> KeyUtils.compareKeyPairs(e, kp))
                    .findFirst()
                    .orElse(null);
            if (prev != null) {
                if (debugEnabled) {
                    log.debug("extractKeyPairs({}) skip duplicate sub-key={}", resourceKey, sk);
                }
                continue;
            }

            kpList.add(kp);
        }

        return kpList;
    }

    public PublicKey extractPublicKey(String resourceKey, Subkey sk) throws IOException, GeneralSecurityException {
        if (sk == null) {
            return null;
        }

        PGPPublicKey pgpKey = Objects.requireNonNull(sk.getPublicKey(), "Missing sub-key public key");
        PublicKeyPacket pgpPacket = Objects.requireNonNull(pgpKey.getPublicKeyPacket(), "Missing public key packet");
        BCPGKey bcKey = Objects.requireNonNull(pgpPacket.getKey(), "Missing BC key");
        if (bcKey instanceof RSAPublicBCPGKey) {
            return extractRSAPublicKey(resourceKey, (RSAPublicBCPGKey) bcKey);
        } else if (bcKey instanceof ECPublicBCPGKey) {
            return extractECPublicKey(resourceKey, (ECPublicBCPGKey) bcKey);
        } else if (bcKey instanceof DSAPublicBCPGKey) {
            return extractDSSPublicKey(resourceKey, (DSAPublicBCPGKey) bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported BC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    public RSAPublicKey extractRSAPublicKey(String resourceKey, RSAPublicBCPGKey bcKey) throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        BigInteger e = bcKey.getPublicExponent();
        BigInteger n = bcKey.getModulus();
        return generatePublicKey(KeyUtils.RSA_ALGORITHM, RSAPublicKey.class, new RSAPublicKeySpec(n, e));
    }

    public PublicKey extractECPublicKey(String resourceKey, ECPublicBCPGKey bcKey) throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        } else if (bcKey instanceof EdDSAPublicBCPGKey) {
            return extractEdDSAPublicKey(resourceKey, (EdDSAPublicBCPGKey) bcKey);
        } else if (bcKey instanceof ECDSAPublicBCPGKey) {
            return extractECDSAPublicKey(resourceKey, (ECDSAPublicBCPGKey) bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported EC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    public ECPublicKey extractECDSAPublicKey(String resourceKey, ECDSAPublicBCPGKey bcKey) throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        ASN1ObjectIdentifier asnId = bcKey.getCurveOID();
        String oid = asnId.getId();
        ECCurves curve = ECCurves.fromOID(oid);
        if (curve == null) {
            throw new InvalidKeySpecException("Not an EC curve OID: " + oid);
        }

        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        BigInteger encPoint = bcKey.getEncodedPoint();
        byte[] octets = encPoint.toByteArray();
        ECPoint w;
        try {
            w = ECCurves.octetStringToEcPoint(octets);
            if (w == null) {
                throw new InvalidKeySpecException("No ECPoint generated for curve=" + curve.getName()
                        + " from octets=" + BufferUtils.toHex(':', octets));
            }
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("Failed (" + e.getClass().getSimpleName() + ")"
                    + " to generate ECPoint for curve=" + curve.getName()
                    + " from octets=" + BufferUtils.toHex(':', octets)
                    + ": " + e.getMessage());
        }

        ECParameterSpec paramSpec = curve.getParameters();
        return generatePublicKey(KeyUtils.EC_ALGORITHM, ECPublicKey.class, new ECPublicKeySpec(w, paramSpec));
    }

    public PublicKey extractEdDSAPublicKey(String resourceKey, EdDSAPublicBCPGKey bcKey)  throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchProviderException("EdDSA not supported");
        }

        throw new NoSuchAlgorithmException("Unsupported EdDSA public key type: " + bcKey.getClass().getSimpleName());
    }

    public DSAPublicKey extractDSSPublicKey(String resourceKey, DSAPublicBCPGKey bcKey) throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        BigInteger p = bcKey.getP();
        BigInteger q = bcKey.getQ();
        BigInteger g = bcKey.getG();
        BigInteger y = bcKey.getY();
        return generatePublicKey(KeyUtils.DSS_ALGORITHM, DSAPublicKey.class, new DSAPublicKeySpec(y, p, q, g));
    }

    protected <K extends PublicKey> K generatePublicKey(String algorithm, Class<K> keyType, KeySpec keySpec)
                throws GeneralSecurityException {
        KeyFactory factory = getKeyFactory(algorithm);
        PublicKey pubKey = factory.generatePublic(keySpec);
        return keyType.cast(pubKey);
    }

    public PrivateKey extractPrivateKey(String resourceKey, Subkey sk, PublicKey pubKey)
            throws IOException, GeneralSecurityException, PGPException {
        if (sk == null) {
            return null;
        }

        PGPPrivateKey pgpKey = Objects.requireNonNull(sk.getPrivateKey(), "Missing sub-key private key");
        BCPGKey bcKey = Objects.requireNonNull(pgpKey.getPrivateKeyDataPacket(), "Missing BC key");
        if (bcKey instanceof RSASecretBCPGKey) {
            return extractRSAPrivateKey(resourceKey, (RSAPublicKey) pubKey, (RSASecretBCPGKey) bcKey);
        } else if (bcKey instanceof ECSecretBCPGKey) {
            return extractECDSAPrivateKey(resourceKey, (ECPublicKey) pubKey, (ECSecretBCPGKey) bcKey);
        } else if (bcKey instanceof EdSecretBCPGKey) {
            return extractEdDSAPrivateKey(resourceKey, pubKey, (EdSecretBCPGKey) bcKey);
        } else if (bcKey instanceof DSASecretBCPGKey) {
            return extractDSSPrivateKey(resourceKey, (DSAPublicKey) pubKey, (DSASecretBCPGKey) bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported BC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    public ECPrivateKey extractECDSAPrivateKey(String resourceKey, ECPublicKey pubKey, ECSecretBCPGKey bcKey)
            throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        ECParameterSpec params = pubKey.getParams();
        BigInteger x = bcKey.getX();
        return generatePrivateKey(KeyUtils.EC_ALGORITHM, ECPrivateKey.class, new ECPrivateKeySpec(x, params));
    }

    public PrivateKey extractEdDSAPrivateKey(String resourceKey, PublicKey pubKey, EdSecretBCPGKey bcKey)
            throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchProviderException("EdDSA not supported");
        }

        throw new NoSuchAlgorithmException("Unsupported EdDSA private key type: " + bcKey.getClass().getSimpleName());
    }

    public RSAPrivateKey extractRSAPrivateKey(String resourceKey, RSAPublicKey pubKey, RSASecretBCPGKey bcKey)
            throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        return generatePrivateKey(KeyUtils.RSA_ALGORITHM, RSAPrivateKey.class,
                new RSAPrivateCrtKeySpec(
                        bcKey.getModulus(),
                        pubKey.getPublicExponent(),
                        bcKey.getPrivateExponent(),
                        bcKey.getPrimeP(),
                        bcKey.getPrimeQ(),
                        bcKey.getPrimeExponentP(),
                        bcKey.getPrimeExponentQ(),
                        bcKey.getCrtCoefficient()));
    }

    public DSAPrivateKey extractDSSPrivateKey(String resourceKey, DSAPublicKey pubKey, DSASecretBCPGKey bcKey)
            throws GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        DSAParams params = pubKey.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in public key");
        }

        return generatePrivateKey(KeyUtils.DSS_ALGORITHM, DSAPrivateKey.class,
            new DSAPrivateKeySpec(bcKey.getX(), params.getP(), params.getQ(), params.getG()));
    }

    protected <K extends PrivateKey> K generatePrivateKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException {
        KeyFactory factory = getKeyFactory(algorithm);
        PrivateKey prvKey = factory.generatePrivate(keySpec);
        return keyType.cast(prvKey);
    }

    protected KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(algorithm);
    }
}
