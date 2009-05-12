/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Signature interface for SSH used to sign or verify packets
 * Usually wraps a javax.crypto.Signature object
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Signature {

    /**
     * Initialize this signature with the given public key and private key.
     * If the private key is null, only signature verification can be performed.
     *
     * @param pubkey
     * @param prvkey
     * @throws Exception
     */
    void init(PublicKey pubkey, PrivateKey prvkey) throws Exception;

    /**
     * Update the computed signature with the given data
     *
     * @param H
     * @param off
     * @param len
     * @throws Exception
     */
    void update(byte[] H, int off, int len) throws Exception;

    /**
     * Verify against the given signature
     *
     * @param sig
     * @return
     * @throws Exception
     */
    boolean verify(byte[] sig) throws Exception;

    /**
     * Compute the signature
     *
     * @return
     * @throws Exception
     */
    byte[] sign() throws Exception;

}
