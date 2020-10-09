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
package org.apache.sshd.common.kex;

import java.math.BigInteger;
import java.util.Collections;
import java.util.NavigableMap;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.LoggingUtils;

/**
 * Key exchange algorithm.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyExchange extends NamedResource, SessionHolder<Session> {
    NavigableMap<Integer, String> GROUP_KEX_OPCODES_MAP = Collections.unmodifiableNavigableMap(
            LoggingUtils.generateMnemonicMap(SshConstants.class, "SSH_MSG_KEX_DH_GEX_"));

    NavigableMap<Integer, String> SIMPLE_KEX_OPCODES_MAP = Collections.unmodifiableNavigableMap(
            LoggingUtils.generateMnemonicMap(SshConstants.class, "SSH_MSG_KEXDH_"));

    /**
     * Initialize the key exchange algorithm.
     *
     * @param  v_s       the server identification string
     * @param  v_c       the client identification string
     * @param  i_s       the server key initialization packet
     * @param  i_c       the client key initialization packet
     * @throws Exception if an error occurs
     */
    void init(byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception;

    /**
     * Process the next packet
     *
     * @param  cmd       the command
     * @param  buffer    the packet contents positioned after the command
     * @return           a boolean indicating if the processing is complete or if more packets are to be received
     * @throws Exception if an error occurs
     */
    boolean next(int cmd, Buffer buffer) throws Exception;

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

    static String getGroupKexOpcodeName(int cmd) {
        String name = GROUP_KEX_OPCODES_MAP.get(cmd);
        if (GenericUtils.isEmpty(name)) {
            return SshConstants.getCommandMessageName(cmd);
        } else {
            return name;
        }
    }

    static String getSimpleKexOpcodeName(int cmd) {
        String name = SIMPLE_KEX_OPCODES_MAP.get(cmd);
        if (GenericUtils.isEmpty(name)) {
            return SshConstants.getCommandMessageName(cmd);
        } else {
            return name;
        }
    }

    // see https://tools.ietf.org/html/rfc8268#section-4
    static boolean isValidDHValue(BigInteger value, BigInteger p) {
        if ((value == null) || (p == null)) {
            return false;
        }

        // 1 < value < p-1
        if (value.compareTo(BigInteger.ONE) <= 0) {
            return false;
        }

        if (value.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            return false;
        }

        return true;
    }
}
