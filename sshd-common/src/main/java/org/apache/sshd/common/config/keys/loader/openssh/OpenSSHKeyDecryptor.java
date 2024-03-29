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

package org.apache.sshd.common.config.keys.loader.openssh;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.session.SessionContext;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface OpenSSHKeyDecryptor {
    boolean isEncrypted();

    byte[] decodePrivateKeyBytes(
            SessionContext session, NamedResource resourceKey, CipherFactory cipherSpec, byte[] privateDataBytes,
            String password)
            throws IOException, GeneralSecurityException;
}
