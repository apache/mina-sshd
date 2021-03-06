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
package org.apache.sshd.client.auth.pubkey;

import java.security.KeyPair;
import java.util.Map;

import org.apache.sshd.common.session.SessionContext;

/**
 * Represents a public key identity
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyIdentity {
    /**
     * @return The {@link KeyPair} identity value
     */
    KeyPair getKeyIdentity();

    /**
     * Proves the public key identity by signing the given data
     *
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  algo      Recommended signature algorithm - if {@code null}/empty then one will be selected based on the
     *                   key type and/or signature factories. <B>Note:</B> even if specific algorithm specified, the
     *                   implementation may disregard and choose another
     * @param  data      Data to sign
     * @return           used algorithm + signed data - using the identity
     * @throws Exception If failed to sign the data
     */
    Map.Entry<String, byte[]> sign(SessionContext session, String algo, byte[] data) throws Exception;
}
