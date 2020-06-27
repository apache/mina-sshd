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

package org.apache.sshd.common.cipher;

import org.apache.sshd.common.AlgorithmNameProvider;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;

/**
 * The reported algorithm name refers to the cipher base name - e.g., &quot;AES&quot;, &quot;ARCFOUR&quot;, etc.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface CipherInformation extends AlgorithmNameProvider, KeySizeIndicator {
    /**
     * @return The actual transformation used - e.g., AES/CBC/NoPadding
     */
    String getTransformation();

    /**
     * @return Size of the initialization vector (in bytes)
     */
    int getIVSize();

    /**
     * @return Size of the authentication tag (AT) in bytes or 0 if this cipher does not support authentication
     */
    int getAuthenticationTagSize();

    /**
     * @return Size of block data used by the cipher (in bytes). For stream ciphers this value is (currently) used to
     *         indicate some average work buffer size to be used for the automatic re-keying mechanism described in
     *         <a href="https://tools.ietf.org/html/rfc4253#section-9">RFC 4253 - Section 9</a>
     */
    int getCipherBlockSize();

    /**
     * @return The block size (in bytes) used to derive the secret key for this cipher
     */
    int getKdfSize();
}
