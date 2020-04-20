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

package org.apache.sshd.common.util.buffer.keys;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Parses a raw {@link PublicKey} from a {@link Buffer}
 *
 * @param  <PUB> Type of {@link PublicKey} being extracted
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface BufferPublicKeyParser<PUB extends PublicKey> {

    BufferPublicKeyParser<PublicKey> EMPTY = new BufferPublicKeyParser<PublicKey>() {
        @Override
        public boolean isKeyTypeSupported(String keyType) {
            return false;
        }

        @Override
        public PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
            throw new NoSuchAlgorithmException(keyType);
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    BufferPublicKeyParser<PublicKey> DEFAULT = aggregate(
            Arrays.asList(
                    RSABufferPublicKeyParser.INSTANCE,
                    DSSBufferPublicKeyParser.INSTANCE,
                    ECBufferPublicKeyParser.INSTANCE,
                    SkECBufferPublicKeyParser.INSTANCE,
                    ED25519BufferPublicKeyParser.INSTANCE,
                    OpenSSHCertPublicKeyParser.INSTANCE,
                    SkED25519BufferPublicKeyParser.INSTANCE));

    /**
     * @param  keyType The key type - e.g., &quot;ssh-rsa&quot, &quot;ssh-dss&quot;
     * @return         {@code true} if this key type is supported by the parser
     */
    boolean isKeyTypeSupported(String keyType);

    /**
     * @param  keyType                  The key type - e.g., &quot;ssh-rsa&quot, &quot;ssh-dss&quot;
     * @param  buffer                   The {@link Buffer} containing the encoded raw public key
     * @return                          The decoded {@link PublicKey}
     * @throws GeneralSecurityException If failed to generate the key
     */
    PUB getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException;

    static BufferPublicKeyParser<PublicKey> aggregate(
            Collection<? extends BufferPublicKeyParser<? extends PublicKey>> parsers) {
        if (GenericUtils.isEmpty(parsers)) {
            return EMPTY;
        }

        return new BufferPublicKeyParser<PublicKey>() {
            @Override
            public boolean isKeyTypeSupported(String keyType) {
                for (BufferPublicKeyParser<? extends PublicKey> p : parsers) {
                    if (p.isKeyTypeSupported(keyType)) {
                        return true;
                    }
                }

                return false;
            }

            @Override
            public PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
                for (BufferPublicKeyParser<? extends PublicKey> p : parsers) {
                    if (p.isKeyTypeSupported(keyType)) {
                        return p.getRawPublicKey(keyType, buffer);
                    }
                }

                throw new NoSuchAlgorithmException("No aggregate matcher for " + keyType);
            }

            @Override
            public String toString() {
                return String.valueOf(parsers);
            }
        };
    }
}
