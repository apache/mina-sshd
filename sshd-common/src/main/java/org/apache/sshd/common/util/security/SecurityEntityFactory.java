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

package org.apache.sshd.common.util.security;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SecurityEntityFactory {

    default CertificateFactory createCertificateFactory(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default Cipher createCipher(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default KeyAgreement createKeyAgreement(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default KeyFactory createKeyFactory(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default KeyPairGenerator createKeyPairGenerator(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default Mac createMac(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default MessageDigest createMessageDigest(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default Signature createSignature(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    default SecureRandom createSecureRandom(String algorithm) throws GeneralSecurityException {
        throw new NoSuchAlgorithmException("Algorithm '" + algorithm + "' not supported (default)");
    }

    class Named implements SecurityEntityFactory {

        private final String name;

        public Named(String name) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "Security provider name must not be empty");
        }

        @Override
        public CertificateFactory createCertificateFactory(String algorithm) throws GeneralSecurityException {
            return CertificateFactory.getInstance(algorithm, name);
        }

        @Override
        public Cipher createCipher(String algorithm) throws GeneralSecurityException {
            return Cipher.getInstance(algorithm, name);
        }

        @Override
        public KeyAgreement createKeyAgreement(String algorithm) throws GeneralSecurityException {
            return KeyAgreement.getInstance(algorithm, name);
        }

        @Override
        public KeyFactory createKeyFactory(String algorithm) throws GeneralSecurityException {
            return KeyFactory.getInstance(algorithm, name);
        }

        @Override
        public KeyPairGenerator createKeyPairGenerator(String algorithm) throws GeneralSecurityException {
            return KeyPairGenerator.getInstance(algorithm, name);
        }

        @Override
        public Mac createMac(String algorithm) throws GeneralSecurityException {
            return Mac.getInstance(algorithm, name);
        }

        @Override
        public MessageDigest createMessageDigest(String algorithm) throws GeneralSecurityException {
            return MessageDigest.getInstance(algorithm, name);
        }

        @Override
        public Signature createSignature(String algorithm) throws GeneralSecurityException {
            return Signature.getInstance(algorithm, name);
        }

        @Override
        public SecureRandom createSecureRandom(String algorithm) throws GeneralSecurityException {
            return SecureRandom.getInstance(algorithm, name);
        }
    }

    class ByProvider implements SecurityEntityFactory {

        private final Provider provider;

        public ByProvider(Provider name) {
            this.provider = ValidateUtils.checkNotNull(name, "Security provider must not be null");
        }

        @Override
        public CertificateFactory createCertificateFactory(String algorithm) throws GeneralSecurityException {
            return CertificateFactory.getInstance(algorithm, provider);
        }

        @Override
        public Cipher createCipher(String algorithm) throws GeneralSecurityException {
            return Cipher.getInstance(algorithm, provider);
        }

        @Override
        public KeyAgreement createKeyAgreement(String algorithm) throws GeneralSecurityException {
            return KeyAgreement.getInstance(algorithm, provider);
        }

        @Override
        public KeyFactory createKeyFactory(String algorithm) throws GeneralSecurityException {
            return KeyFactory.getInstance(algorithm, provider);
        }

        @Override
        public KeyPairGenerator createKeyPairGenerator(String algorithm) throws GeneralSecurityException {
            return KeyPairGenerator.getInstance(algorithm, provider);
        }

        @Override
        public Mac createMac(String algorithm) throws GeneralSecurityException {
            return Mac.getInstance(algorithm, provider);
        }

        @Override
        public MessageDigest createMessageDigest(String algorithm) throws GeneralSecurityException {
            return MessageDigest.getInstance(algorithm, provider);
        }

        @Override
        public Signature createSignature(String algorithm) throws GeneralSecurityException {
            return Signature.getInstance(algorithm, provider);
        }

        @Override
        public SecureRandom createSecureRandom(String algorithm) throws GeneralSecurityException {
            return SecureRandom.getInstance(algorithm, provider);
        }
    }

    enum Default implements SecurityEntityFactory {

        INSTANCE;

        @Override
        public CertificateFactory createCertificateFactory(String algorithm) throws GeneralSecurityException {
            return CertificateFactory.getInstance(algorithm);
        }

        @Override
        public Cipher createCipher(String algorithm) throws GeneralSecurityException {
            return Cipher.getInstance(algorithm);
        }

        @Override
        public KeyAgreement createKeyAgreement(String algorithm) throws GeneralSecurityException {
            return KeyAgreement.getInstance(algorithm);
        }

        @Override
        public KeyFactory createKeyFactory(String algorithm) throws GeneralSecurityException {
            return KeyFactory.getInstance(algorithm);
        }

        @Override
        public KeyPairGenerator createKeyPairGenerator(String algorithm) throws GeneralSecurityException {
            return KeyPairGenerator.getInstance(algorithm);
        }

        @Override
        public Mac createMac(String algorithm) throws GeneralSecurityException {
            return Mac.getInstance(algorithm);
        }

        @Override
        public MessageDigest createMessageDigest(String algorithm) throws GeneralSecurityException {
            return MessageDigest.getInstance(algorithm);
        }

        @Override
        public Signature createSignature(String algorithm) throws GeneralSecurityException {
            return Signature.getInstance(algorithm);
        }

        @Override
        public SecureRandom createSecureRandom(String algorithm) throws GeneralSecurityException {
            return SecureRandom.getInstance(algorithm);
        }
    }
}
