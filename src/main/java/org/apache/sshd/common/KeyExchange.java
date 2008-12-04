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

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.session.AbstractSession;

/**
 * Key exchange algorithm.
 */
public interface KeyExchange {

    /**
     * Initialize the key exchange algorithm.
     *
     * @param session the session using this algorithm
     * @param V_S the server identification string
     * @param V_C the client identification string
     * @param I_S the server key init packet
     * @param I_C the client key init packet
     * @throws Exception if an error occurs
     */
    void init(AbstractSession session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception;

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
     * Retrieves the computed H parameter
     *
     * @return
     */
    byte[] getH();

    /**
     * Retrieves the computed K parameter
     *
     * @return
     */
    byte[] getK();

}