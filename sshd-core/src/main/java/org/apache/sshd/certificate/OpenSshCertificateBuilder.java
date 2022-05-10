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

package org.apache.sshd.certificate;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.OpenSshCertificate.Type;
import org.apache.sshd.common.config.keys.OpenSshCertificateImpl;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Holds all the data necessary to create a signed OpenSSH Certificate
 */
public class OpenSshCertificateBuilder {

    // given a supported key type, map to the concrete OpenSSH Certificate type
    protected static final Map<String, String> SIGNATURE_ALGORITHM_MAP
            = MapEntryUtils.MapBuilder.<String, String> builder()
                    .put(KeyPairProvider.SSH_RSA, KeyPairProvider.SSH_RSA_CERT)
                    .put(KeyPairProvider.SSH_ED25519, KeyPairProvider.SSH_ED25519_CERT)
                    .put(KeyPairProvider.ECDSA_SHA2_NISTP256, KeyPairProvider.SSH_ECDSA_SHA2_NISTP256_CERT)
                    .put(KeyPairProvider.ECDSA_SHA2_NISTP384, KeyPairProvider.SSH_ECDSA_SHA2_NISTP384_CERT)
                    .put(KeyPairProvider.ECDSA_SHA2_NISTP521, KeyPairProvider.SSH_ECDSA_SHA2_NISTP521_CERT)
                    .build();

    protected final Type type;
    protected PublicKey publicKey;
    protected long serial;
    protected String id;
    protected Collection<String> principals;
    // criticalOptions and extensions must be lexically ordered by "name" if they appear in the
    // sequence. Each named option may only appear once in a certificate.
    protected List<OpenSshCertificate.CertificateOption> criticalOptions;
    protected List<OpenSshCertificate.CertificateOption> extensions;
    // match ssh-keygen behavior where the default would be forever
    protected long validAfter = OpenSshCertificate.MIN_EPOCH;
    // match ssh-keygen behavior where the default would be forever
    protected long validBefore = OpenSshCertificate.INFINITY;
    protected byte[] nonce;

    protected OpenSshCertificateBuilder(Type type) {
        super();
        this.type = type;
    }

    public static OpenSshCertificateBuilder userCertificate() {
        return new OpenSshCertificateBuilder(Type.USER);
    }

    public static OpenSshCertificateBuilder hostCertificate() {
        return new OpenSshCertificateBuilder(Type.HOST);
    }

    public OpenSshCertificateBuilder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public OpenSshCertificateBuilder serial(long serial) {
        this.serial = serial;
        return this;
    }

    public OpenSshCertificateBuilder id(String id) {
        this.id = id;
        return this;
    }

    public OpenSshCertificateBuilder principals(Collection<String> principals) {
        this.principals = principals;
        return this;
    }

    public OpenSshCertificateBuilder criticalOptions(List<OpenSshCertificate.CertificateOption> criticalOptions) {
        validateOptions(criticalOptions);
        this.criticalOptions = lexicallyOrderOptions(criticalOptions);
        return this;
    }

    public OpenSshCertificateBuilder extensions(List<OpenSshCertificate.CertificateOption> extensions) {
        validateOptions(extensions);
        this.extensions = lexicallyOrderOptions(extensions);
        return this;
    }

    public OpenSshCertificateBuilder validAfter(long validAfter) {
        this.validAfter = validAfter;
        return this;
    }

    public OpenSshCertificateBuilder nonce(byte[] nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * If null, uses {@link OpenSshCertificate#MIN_EPOCH}
     *
     * @param  validAfter {@link Instant} to use for validBefore
     * @return            Self reference
     */
    public OpenSshCertificateBuilder validAfter(Instant validAfter) {
        if (validAfter == null) {
            return validAfter(OpenSshCertificate.MIN_EPOCH);
        } else if (Instant.EPOCH.compareTo(validAfter) <= 0) {
            return validAfter(validAfter.getEpochSecond());
        }
        throw new IllegalArgumentException("Valid-after cannot be < epoch");
    }

    public OpenSshCertificateBuilder validBefore(long validBefore) {
        this.validBefore = validBefore;
        return this;
    }

    /**
     * If null, uses {@link OpenSshCertificate#INFINITY}
     *
     * @param  validBefore {@link Instant} to use for validBefore
     * @return             Self reference
     */
    public OpenSshCertificateBuilder validBefore(Instant validBefore) {
        if (validBefore == null) {
            return validBefore(OpenSshCertificate.INFINITY);
        } else if (Instant.EPOCH.compareTo(validBefore) <= 0) {
            return validBefore(validBefore.getEpochSecond());
        }
        throw new IllegalArgumentException("Valid-before cannot be < epoch");
    }

    protected void validate() {
        // nonce should be 16 or 32 bytes according to
        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys#L151-L153
        if (nonce != null && (nonce.length != 16 && nonce.length != 32)) {
            throw new IllegalStateException("'nonce' must be 16 or 32 bytes");
        }
        if (type == null) {
            throw new IllegalStateException("'type' is required");
        }
        if (id == null) {
            throw new IllegalStateException("'id' is required");
        }
        if (publicKey == null) {
            throw new IllegalStateException("'publicKey' is required");
        }
    }

    /**
     * Creates a certificate signed with the given CA key. For RSA keys "rsa-sha2-512" is used for the signature.
     *
     * @param  caKeypair CA key used to sign
     * @return           the signed certificate
     * @throws Exception if an error occurred
     */
    public OpenSshCertificate sign(KeyPair caKeypair) throws Exception {
        return sign(caKeypair, null);
    }

    /**
     * Creates a certificate signed with the given CA key using the specified signature algorithm. If a signature
     * algorithm is given, it must be appropriate for the CA key type, otherwise an exception is thrown. If
     * {@code signatureAlgorithm == null}, an appropriate signature algorithm is chosen automatically, for RSA keys
     * "rsa-sha2-512" is used then.
     *
     * @param  caKeypair          CA key used to sign
     * @param  signatureAlgorithm to use; if {@code null} automatically chosen based on the CA key type
     * @return                    the signed certificate
     * @throws Exception          if an error occurred
     */
    public OpenSshCertificate sign(KeyPair caKeypair, String signatureAlgorithm) throws Exception {
        validate();

        final String publicKeyType = KeyUtils.getKeyType(publicKey);
        final String certType = SIGNATURE_ALGORITHM_MAP.get(publicKeyType);

        // only certain kind of keys can be OpenSSH Certificates
        if (certType == null) {
            throw new UnsupportedOperationException(
                    "unsupported public key type '" + publicKeyType + "' for OpenSSH Certificate");
        }

        final OpenSshCertificateImpl cert = new OpenSshCertificateImpl();
        cert.setKeyType(certType);
        cert.setType(type);
        cert.setCertPubKey(publicKey);
        cert.setSerial(serial);
        cert.setId(id);
        if (principals != null && !principals.isEmpty()) {
            cert.setPrincipals(new ArrayList<>(principals));
        }
        if (criticalOptions != null && !criticalOptions.isEmpty()) {
            cert.setCriticalOptions(new ArrayList<>(criticalOptions));
        }
        if (extensions != null && !extensions.isEmpty()) {
            cert.setExtensions(new ArrayList<>(extensions));
        }
        cert.setValidAfter(validAfter);
        cert.setValidBefore(validBefore);

        cert.setCaPubKey(caKeypair.getPublic());

        if (nonce != null) {
            cert.setNonce(nonce);
        } else {
            SecureRandom rand = new SecureRandom();
            byte[] tempNonce = new byte[32];
            rand.nextBytes(tempNonce);
            cert.setNonce(tempNonce);
        }

        String algo = KeyUtils.getKeyType(caKeypair.getPublic());
        NamedFactory<? extends Signature> factory;
        if (signatureAlgorithm != null) {
            ValidateUtils.checkTrue(KeyUtils.getAllEquivalentKeyTypes(algo).contains(signatureAlgorithm),
                    "Invalid CA signature algorithm %s for CA key type %s", signatureAlgorithm, algo);
            algo = signatureAlgorithm;
            factory = BuiltinSignatures.fromFactoryName(algo);
        } else {
            factory = SignatureFactory.resolveSignatureFactory(algo, BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE);
        }
        Signature signer = factory == null ? null : factory.create();
        ValidateUtils.checkNotNull(signer, "No signer could be located for signature algorithm=%s", algo);

        final ByteArrayBuffer toBeSignedBuf = new ByteArrayBuffer();
        toBeSignedBuf.putRawPublicKey(cert);

        final byte[] toSign = toBeSignedBuf.getCompactData();
        signer.initSigner(null, caKeypair.getPrivate());
        signer.update(null, toSign);

        final ByteArrayBuffer tmpBuffer = new ByteArrayBuffer();
        tmpBuffer.putString(factory.getName());
        tmpBuffer.putBytes(signer.sign(null));

        cert.setMessage(toSign);
        cert.setSignature(tmpBuffer.getCompactData());

        return cert;
    }

    /**
     * Validates that there are no duplicate options.
     *
     * @param  options                  the options to check
     * @throws IllegalArgumentException if there are duplicates
     */
    private void validateOptions(List<OpenSshCertificate.CertificateOption> options) {
        if (options != null && !options.isEmpty()) {
            // check if any duplicates
            Set<String> names = new HashSet<>();
            Set<String> duplicates = options.stream().filter(option -> !names.add(option.getName()))
                    .map(OpenSshCertificate.CertificateOption::getName)
                    .collect(Collectors.toSet());
            if (!duplicates.isEmpty()) {
                throw new IllegalArgumentException("Duplicate option: " + duplicates);
            }
        }
    }

    /**
     * Lexically orders certificate options by name.
     *
     * @param  options the options to order
     * @return         a list containing the options in lexical order
     */
    private List<OpenSshCertificate.CertificateOption> lexicallyOrderOptions(
            List<OpenSshCertificate.CertificateOption> options) {
        if (options != null && !options.isEmpty()) {
            return options.stream()
                    .sorted(Comparator.comparing(OpenSshCertificate.CertificateOption::getName))
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }
}
