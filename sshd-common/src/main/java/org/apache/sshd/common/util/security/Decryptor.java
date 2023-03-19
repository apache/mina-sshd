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

/**
 * Something that can decrypt encrypted data given a password.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Decryptor {

    /**
     * Decrypts encrypted bytes, using the given password as decryption key.
     * <p>
     * The encrypted data must contain enough information about the encryption algorithm used so that it can be
     * decrypted at all.
     * </p>
     * <p>
     * If the password is wrong, the method may return wrongly decrypted data. If decryption fails, it may return
     * {@code null} or throw a {@link GeneralSecurityException}.
     * </p>
     * <p>
     * The caller is responsible for eventually clearing the {@code password} and the decrypted data returned.
     * </p>
     *
     * @param  encrypted                data to decrypt
     * @param  password                 decryption key
     * @return                          decrypted data, possibly {@code null} if decryption failed
     * @throws GeneralSecurityException may be thrown if decryption failed
     */
    byte[] decrypt(byte[] encrypted, char[] password) throws GeneralSecurityException;

}
