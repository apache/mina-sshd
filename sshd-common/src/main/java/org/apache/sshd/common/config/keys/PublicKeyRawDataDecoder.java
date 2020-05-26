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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Map;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.NumberUtils;

/**
 * @param  <PUB> Generic {@link PublicKey} type
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyRawDataDecoder<PUB extends PublicKey> {
    /**
     * @param  session                  The {@link SessionContext} for invoking this command - may be {@code null} if
     *                                  not invoked within a session context (e.g., offline tool or session unknown).
     * @param  keyType                  The {@code OpenSSH} reported key type
     * @param  keyData                  The key data bytes in {@code OpenSSH} format (after BASE64 decoding) - ignored
     *                                  if {@code null}/empty
     * @param  headers                  Any headers that may have been available when data was read
     * @return                          The decoded {@link PublicKey} - or {@code null} if no data
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    default PUB decodePublicKey(
            SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        return decodePublicKey(session, keyType, keyData, 0, NumberUtils.length(keyData), headers);
    }

    default PUB decodePublicKey(
            SessionContext session, String keyType, byte[] keyData, int offset, int length, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (length <= 0) {
            return null;
        }

        try (InputStream stream = new ByteArrayInputStream(keyData, offset, length)) {
            return decodePublicKeyByType(session, keyType, stream, headers);
        }
    }

    PUB decodePublicKeyByType(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException;

    /**
     * @param  session                  The {@link SessionContext} for invoking this command - may be {@code null} if
     *                                  not invoked within a session context (e.g., offline tool or session unknown).
     * @param  keyType                  The reported / encode key type
     * @param  keyData                  The key data bytes stream positioned after the key type decoding and making sure
     *                                  it is one of the supported types
     * @param  headers                  Any headers that may have been available when data was read
     * @return                          The decoded {@link PublicKey}
     * @throws IOException              If failed to read from the data stream
     * @throws GeneralSecurityException If failed to generate the key
     */
    PUB decodePublicKey(SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException;
}
