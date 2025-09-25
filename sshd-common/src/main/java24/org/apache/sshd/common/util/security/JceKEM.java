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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;

enum JceKEM implements KEMFactory {

    INSTANCE;

    // See https://datatracker.ietf.org/doc/html/draft-ietf-lamps-kyber-certificates-11

    // Sequence, length 1202 (3 bytes), Sequence, length 11, OID, length 9, 9 bytes OID, Bit String, length 1185 (3
    // bytes), zero unused bits. OID = 2.16.840.101.3.4.4.2
    private static final byte[] ML768_X509_PREFIX = { 0x30, (byte) 0x82, 0x04, (byte) 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60,
            (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, (byte) 0x82, 0x04, (byte) 0xa1, 0x00 };
    // Sequence, length 1586 (3 bytes), Sequence, length 11, OID, length 9, 9 bytes OID, Bit String, length 1569 (3
    // bytes), zero unused bits. OID = 2.16.840.101.3.4.4.3
    private static final byte[] ML1024_X509_PREFIX = { 0x30, (byte) 0x82, 0x06, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03, 0x03, (byte) 0x82, 0x06, 0x21, 0x00 };

    @Override
    public KEM get(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        javax.crypto.KEM kem = provider == null
                ? javax.crypto.KEM.getInstance(algorithm)
                : javax.crypto.KEM.getInstance(algorithm, provider);
        if (KEM.ML_KEM_768.equalsIgnoreCase(algorithm)) {
            return new KEMWrapper(kem, KEM.ML_KEM_768, provider, 1184, 1088, ML768_X509_PREFIX);
        } else if (KEM.ML_KEM_1024.equalsIgnoreCase(algorithm)) {
            return new KEMWrapper(kem, KEM.ML_KEM_1024, provider, 1568, 1568, ML1024_X509_PREFIX);
        }
        throw new NoSuchAlgorithmException(algorithm + " not supported");
    }

    @Override
    public boolean isSupported(String algorithm) {
        if (KEM.ML_KEM_768.equalsIgnoreCase(algorithm) || KEM.ML_KEM_1024.equalsIgnoreCase(algorithm)) {
            try {
                return javax.crypto.KEM.getInstance(algorithm) != null;
            } catch (NoSuchAlgorithmException e) {
                return false;
            }
        }
        return false;
    }

    private static class KEMWrapper implements KEM {

        private final javax.crypto.KEM kem;

        private final String algorithm;

        private final Provider provider;

        private final int encapKeyLength;

        private final int cipherTextLength;

        private final byte[] prefix;

        KEMWrapper(javax.crypto.KEM kem, String algorithm, Provider provider, int encapKeyLength, int cipherTextLength,
                byte[] prefix) {
            this.algorithm = algorithm;
            this.provider = provider;
            this.encapKeyLength = encapKeyLength;
            this.cipherTextLength = cipherTextLength;
            this.prefix = prefix;
            this.kem = kem;
        }

        @Override
        public String toString() {
            return kem.getClass().getName();
        }

        @Override
        public boolean isSupported() {
            return true;
        }

        @Override
        public Client getClient() {
            return new Client();
        }

        @Override
        public Server getServer() {
            return new Server();
        }

        private class Client implements KEM.Client {

            private Decapsulator dec;

            private byte[] pubKey;

            Client() {
                super();
            }

            private byte[] extractFromX509(byte[] x509, byte[] prefix, int length) {
                return Arrays.copyOfRange(x509, prefix.length, prefix.length + length);
            }

            @Override
            public void init() {
                try {
                    KeyPairGenerator generator = provider == null
                            ? KeyPairGenerator.getInstance(algorithm)
                            : KeyPairGenerator.getInstance(algorithm, provider);
                    KeyPair kp = generator.generateKeyPair();
                    dec = kem.newDecapsulator(kp.getPrivate());
                    pubKey = extractFromX509(kp.getPublic().getEncoded(), prefix, encapKeyLength);
                } catch (GeneralSecurityException e) {
                    throw new IllegalStateException(e.getMessage(), e);
                }
            }

            @Override
            public byte[] getPublicKey() {
                return pubKey;
            }

            @Override
            public byte[] extractSecret(byte[] encapsulated) {
                try {
                    return dec.decapsulate(encapsulated).getEncoded();
                } catch (DecapsulateException e) {
                    throw new IllegalArgumentException(e.getMessage(), e);
                }
            }

            @Override
            public int getEncapsulationLength() {
                return cipherTextLength;
            }
        }

        private class Server implements KEM.Server {

            private Encapsulated encapsulation;

            Server() {
                super();
            }

            private PublicKey createKey(byte[] raw, int from, int length) throws GeneralSecurityException {
                KeyFactory factory = provider == null
                        ? KeyFactory.getInstance(algorithm)
                        : KeyFactory.getInstance(algorithm, provider);
                byte[] x509 = Arrays.copyOf(prefix, prefix.length + length);
                System.arraycopy(raw, from, x509, prefix.length, length);
                return factory.generatePublic(new X509EncodedKeySpec(x509));
            }

            @Override
            public int getPublicKeyLength() {
                return encapKeyLength;
            }

            @Override
            public byte[] init(byte[] publicKey) {
                int pkBytes = getPublicKeyLength();
                if (publicKey.length < pkBytes) {
                    throw new IllegalArgumentException("KEM public key too short: " + publicKey.length);
                }
                try {
                    Encapsulator enc = kem.newEncapsulator(createKey(publicKey, 0, pkBytes));
                    encapsulation = enc.encapsulate();
                    return Arrays.copyOfRange(publicKey, pkBytes, publicKey.length);
                } catch (GeneralSecurityException e) {
                    throw new IllegalArgumentException(e.getMessage(), e);
                }
            }

            @Override
            public byte[] getSecret() {
                return encapsulation.key().getEncoded();
            }

            @Override
            public byte[] getEncapsulation() {
                return encapsulation.encapsulation();
            }
        }
    }
}
