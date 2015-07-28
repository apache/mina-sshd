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
package org.apache.sshd.common.kex;

import java.security.PublicKey;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Key exchange algorithm.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyExchange {

    /**
     * Initialize the key exchange algorithm.
     *
     * @param session the session using this algorithm
     * @param v_s     the server identification string
     * @param v_c     the client identification string
     * @param i_s     the server key init packet
     * @param i_c     the client key init packet
     * @throws Exception if an error occurs
     */
    void init(AbstractSession session, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception;

    /**
     * Process the next packet
     *
     * @param buffer the packet
     * @return a boolean indicating if the processing is complete or if more packets are to be received
     * @throws Exception if an error occurs
     */
    boolean next(Buffer buffer) throws Exception;

    /**
     * The message digest used by this key exchange algorithm.
     *
     * @return the message digest
     */
    Digest getHash();

    /**
     * Retrieves the computed {@code h} parameter
     *
     * @return The {@code h} parameter
     */
    byte[] getH();

    /**
     * Retrieves the computed k parameter
     *
     * @return The {@code k} parameter
     */
    byte[] getK();

    /**
     * Retrieves the server's key
     *
     * @return The server's {@link PublicKey}
     */
    PublicKey getServerKey();
}
