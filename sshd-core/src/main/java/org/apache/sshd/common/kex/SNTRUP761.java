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
package org.apache.sshd.common.kex;

import java.util.Arrays;

import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;

/**
 * A Bouncy Castle implementation of the sntrup761 key encapsulation method (KEM).
 */
final class SNTRUP761 {

    private SNTRUP761() {
        // No instantiation
    }

    static boolean isSupported() {
        if (SecurityUtils.isFipsMode()) {
            return false;
        }
        try {
            return SNTRUPrimeParameters.sntrup761.getSessionKeySize() == 256; // BC < 1.78 had only 128
        } catch (Throwable e) {
            return false;
        }
    }

    static class Client implements KeyEncapsulationMethod.Client {

        private SNTRUPrimeKEMExtractor extractor;
        private SNTRUPrimePublicKeyParameters publicKey;

        Client() {
            super();
        }

        @Override
        public void init() {
            SNTRUPrimeKeyPairGenerator gen = new SNTRUPrimeKeyPairGenerator();
            gen.init(new SNTRUPrimeKeyGenerationParameters(JceRandom.getGlobalInstance(), SNTRUPrimeParameters.sntrup761));
            AsymmetricCipherKeyPair pair = gen.generateKeyPair();
            extractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters) pair.getPrivate());
            publicKey = (SNTRUPrimePublicKeyParameters) pair.getPublic();
        }

        @Override
        public byte[] getPublicKey() {
            return publicKey.getEncoded();
        }

        @Override
        public byte[] extractSecret(byte[] encapsulated) {
            if (encapsulated.length != extractor.getEncapsulationLength()) {
                throw new IllegalArgumentException("KEM encpsulation has wrong length: " + encapsulated.length);
            }
            return extractor.extractSecret(encapsulated);
        }

        @Override
        public int getEncapsulationLength() {
            return extractor.getEncapsulationLength();
        }
    }

    static class Server implements KeyEncapsulationMethod.Server {

        private SecretWithEncapsulation value;

        Server() {
            super();
        }

        @Override
        public int getPublicKeyLength() {
            return SNTRUPrimeParameters.sntrup761.getPublicKeyBytes();
        }

        @Override
        public byte[] init(byte[] publicKey) {
            int pkBytes = getPublicKeyLength();
            if (publicKey.length < pkBytes) {
                throw new IllegalArgumentException("KEM public key too short: " + publicKey.length);
            }
            byte[] pk = Arrays.copyOf(publicKey, pkBytes);
            SNTRUPrimeKEMGenerator kemGenerator = new SNTRUPrimeKEMGenerator(JceRandom.getGlobalInstance());
            SNTRUPrimePublicKeyParameters params = new SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters.sntrup761, pk);
            value = kemGenerator.generateEncapsulated(params);
            return Arrays.copyOfRange(publicKey, pkBytes, publicKey.length);
        }

        @Override
        public byte[] getSecret() {
            return value.getSecret();
        }

        @Override
        public byte[] getEncapsulation() {
            return value.getEncapsulation();
        }

    }
}
