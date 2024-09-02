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

/**
 * General interface for key encapsulation methods (KEM).
 */
public interface KeyEncapsulationMethod {

    /**
     * Client-side KEM operations.
     */
    interface Client {

        /**
         * Initializes the KEM and generates a new key pair.
         */
        void init();

        /**
         * Gets the KEM public key.
         *
         * @return the KEM public key.
         */
        byte[] getPublicKey();

        /**
         * Extracts the secret from an encapsulation ciphertext.
         *
         * @param  encapsulated             ciphertext to process.
         * @return                          the secret from an encapsulation ciphertext.
         * @throws IllegalArgumentException if {@code encapsulated} doesn't have the expected length
         * @throws NullPointerException     if {@code encapsulated == null}
         */
        byte[] extractSecret(byte[] encapsulated);

        /**
         * Gets the required encapsulation length in bytes.
         *
         * @return the length required for a valid encapsulation ciphertext.
         */
        int getEncapsulationLength();
    }

    /**
     * Server-side KEM operations.
     */
    interface Server {

        /**
         * Retrieves the required length of the KEM public key, in bytes.
         *
         * @return the length of the key
         */
        int getPublicKeyLength();

        /**
         * Initializes the KEM with a public key received from a client and prepares an encapsulated secret.
         *
         * @param  publicKey                data received from the client, expected to contain the public key at the
         *                                  start
         * @return                          the remaining bytes of {@code publicKey} after the public key
         *
         * @throws IllegalArgumentException if {@code publicKey} does not have enough bytes for a valid public key
         * @throws NullPointerException     if {@code publicKey == null}
         */
        byte[] init(byte[] publicKey);

        /**
         * Retrieves the secret.
         *
         * @return the secret, not encapsulated
         */
        byte[] getSecret();

        /**
         * Retrieves the encapsulation of the secret.
         *
         * @return the encapsulation of the secret that may be sent to the client
         */
        byte[] getEncapsulation();
    }

    Client getClient();

    Server getServer();
}
