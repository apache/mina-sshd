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

import java.util.Base64;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyEntryDataResolver {
    PublicKeyEntryDataResolver DEFAULT = new PublicKeyEntryDataResolver() {
        @Override
        public String toString() {
            return "DEFAULT";
        }
    };

    /**
     * Decodes the public key entry data bytes from their string representation - by default it assume {@link Base64}
     * encoding.
     *
     * @param  encData The encoded data - ignored if {@code null}/empty
     * @return         The decoded data bytes
     */
    default byte[] decodeEntryKeyData(String encData) {
        if (GenericUtils.isEmpty(encData)) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(encData);
    }

    /**
     * Encodes the public key entry data bytes into their string representation - by default it assume {@link Base64}
     * encoding.
     *
     * @param  keyData The key data bytes - ignored if {@code null}/empty
     * @return         The encoded data bytes
     */
    default String encodeEntryKeyData(byte[] keyData) {
        if (NumberUtils.isEmpty(keyData)) {
            return "";
        }

        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(keyData);
    }
}
