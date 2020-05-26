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
package org.apache.sshd.common.config.keys.loader;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PrivateKeyObfuscator {
    /**
     * @return Basic cipher used to obfuscate
     */
    String getCipherName();

    /**
     * @return A {@link List} of the supported key sizes - <B>Note:</B> every call returns a and <U>un-modifiable</U>
     *         instance.
     */
    List<Integer> getSupportedKeySizes();

    /**
     * @param  <A>         Appendable generic type
     * @param  sb          The {@link Appendable} instance to update
     * @param  encContext
     * @return             Same appendable instance
     * @throws IOException
     */
    <A extends Appendable> A appendPrivateKeyEncryptionContext(
            A sb, PrivateKeyEncryptionContext encContext)
            throws IOException;

    /**
     * @param  encContext               The encryption context
     * @return                          An initialization vector suitable to the specified context
     * @throws GeneralSecurityException
     */
    byte[] generateInitializationVector(PrivateKeyEncryptionContext encContext)
            throws GeneralSecurityException;

    /**
     * @param  bytes                    Original bytes
     * @param  encContext               The encryption context
     * @param  encryptIt                If {@code true} then encrypt the original bytes, otherwise decrypt them
     * @return                          The result of applying the cipher to the original bytes
     * @throws IOException              If malformed input
     * @throws GeneralSecurityException If cannot encrypt/decrypt
     */
    byte[] applyPrivateKeyCipher(
            byte[] bytes, PrivateKeyEncryptionContext encContext, boolean encryptIt)
            throws IOException, GeneralSecurityException;
}
