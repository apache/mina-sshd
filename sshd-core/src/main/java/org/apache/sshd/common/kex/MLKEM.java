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
import java.util.Objects;

import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.random.JceRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * An implementation of the mlkem768 key encapsulation method (KEM), formerly known as Kyber, using Bouncy Castle. But
 * see appendix C of FIPS 203 ("Differences From the CRYSTALS-Kyber Submission").
 * <p>
 * NIST specifies that they removed a hash in the encapsulation/decapsulation methods.
 * </p>
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf">NIST FIPS 203</a>
 */
final class MLKEM {

    enum Parameters implements OptionalFeature {
        // For key sizes see NIST FIPS 203, section 8, table 3. Bouncy Castle does not expose the
        // public key sizes through its API. (Though they compute them internally.)
        mlkem768(1184) {

            @Override
            Object getMLKEMParameters() {
                return MLKEMParameters.ml_kem_768;
            }
        },
        mlkem1024(1568) {

            @Override
            Object getMLKEMParameters() {
                return MLKEMParameters.ml_kem_1024;
            }
        };

        private final int publicKeySize;

        Parameters(int publicKeySize) {
            this.publicKeySize = publicKeySize;
        }

        // Return type is Object on purpose. We want delayed class loading here so that we can use this
        // even if Bouncy Castle is not present. (If it isn't, we'll return false from isSupported at
        // run-time, and then never use this algorithm.)
        abstract Object getMLKEMParameters();

        int getPublicKeySize() {
            return publicKeySize;
        }

        @Override
        public boolean isSupported() {
            try {
                // If we get a ClassNotFoundException or some such, we return false.
                return getMLKEMParameters() != null;
            } catch (Throwable e) {
                return false;
            }
        }
    }

    private MLKEM() {
        // No instantiation
    }

    static KeyEncapsulationMethod.Client getClient(Parameters parameters) {
        return new Client(parameters);
    }

    static KeyEncapsulationMethod.Server getServer(Parameters parameters) {
        return new Server(parameters);
    }

    private static class Client implements KeyEncapsulationMethod.Client {

        private final Parameters parameters;

        private MLKEMExtractor extractor;
        private MLKEMPublicKeyParameters publicKey;

        Client(Parameters parameters) {
            this.parameters = Objects.requireNonNull(parameters, "No MLKEM.Parameters given");
        }

        @Override
        public void init() {
            MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
            gen.init(new MLKEMKeyGenerationParameters(JceRandom.getGlobalInstance(),
                    (MLKEMParameters) parameters.getMLKEMParameters()));
            AsymmetricCipherKeyPair pair = gen.generateKeyPair();
            extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters) pair.getPrivate());
            publicKey = (MLKEMPublicKeyParameters) pair.getPublic();
        }

        @Override
        public byte[] getPublicKey() {
            return publicKey.getEncoded();
        }

        @Override
        public byte[] extractSecret(byte[] encapsulated) {
            if (encapsulated.length != getEncapsulationLength()) {
                throw new IllegalArgumentException("KEM encpsulation has wrong length: " + encapsulated.length);
            }
            return extractor.extractSecret(encapsulated);
        }

        @Override
        public int getEncapsulationLength() {
            return extractor.getEncapsulationLength();
        }
    }

    private static class Server implements KeyEncapsulationMethod.Server {

        private final Parameters parameters;

        private SecretWithEncapsulation value;

        Server(Parameters parameters) {
            this.parameters = Objects.requireNonNull(parameters, "No MLKEM.Parameters given");
        }

        @Override
        public int getPublicKeyLength() {
            return parameters.getPublicKeySize();
        }

        @Override
        public byte[] init(byte[] publicKey) {
            int pkBytes = getPublicKeyLength();
            if (publicKey.length < pkBytes) {
                throw new IllegalArgumentException("KEM public key too short: " + publicKey.length);
            }
            byte[] pk = Arrays.copyOf(publicKey, pkBytes);
            MLKEMGenerator kemGenerator = new MLKEMGenerator(JceRandom.getGlobalInstance());
            MLKEMPublicKeyParameters params = new MLKEMPublicKeyParameters((MLKEMParameters) parameters.getMLKEMParameters(),
                    pk);
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
