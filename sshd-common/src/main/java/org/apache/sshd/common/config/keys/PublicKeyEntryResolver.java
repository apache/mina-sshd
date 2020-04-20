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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import org.apache.sshd.common.session.SessionContext;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PublicKeyEntryResolver {
    /**
     * A resolver that ignores all input
     */
    PublicKeyEntryResolver IGNORING = new PublicKeyEntryResolver() {
        @Override
        public PublicKey resolve(SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
                throws IOException, GeneralSecurityException {
            return null;
        }

        @Override
        public String toString() {
            return "IGNORING";
        }
    };

    /**
     * A resolver that fails on all input
     */
    PublicKeyEntryResolver FAILING = new PublicKeyEntryResolver() {
        @Override
        public PublicKey resolve(SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
                throws IOException, GeneralSecurityException {
            throw new InvalidKeySpecException("Failing resolver on key type=" + keyType);
        }

        @Override
        public String toString() {
            return "FAILING";
        }
    };

    /**
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  keyType                  The {@code OpenSSH} reported key type
     * @param  keyData                  The {@code OpenSSH} encoded key data
     * @param  headers                  Any headers that may have been available when data was read
     * @return                          The extracted {@link PublicKey} - ignored if {@code null}
     * @throws IOException              If failed to parse the key data
     * @throws GeneralSecurityException If failed to generate the key
     */
    PublicKey resolve(SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException;
}
