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
package org.apache.sshd.common;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;

/**
 * This interface defines constants for the SSH protocol.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SshConstants {
    public static final int DEFAULT_PORT = 22;

    /** Converts non-positive port value to {@value #DEFAULT_PORT} */
    public static final IntUnaryOperator TO_EFFECTIVE_PORT = port -> (port > 0) ? port : DEFAULT_PORT;

    //
    // SSH message identifiers
    //

    public static final byte SSH_MSG_DISCONNECT = 1;
    public static final byte SSH_MSG_IGNORE = 2;
    public static final byte SSH_MSG_UNIMPLEMENTED = 3;
    public static final byte SSH_MSG_DEBUG = 4;
    public static final byte SSH_MSG_SERVICE_REQUEST = 5;
    public static final byte SSH_MSG_SERVICE_ACCEPT = 6;

    public static final byte SSH_MSG_KEXINIT = 20;
    public static final int MSG_KEX_COOKIE_SIZE = 16;
    public static final byte SSH_MSG_NEWKEYS = 21;

    public static final byte SSH_MSG_KEX_FIRST = 30;
    public static final byte SSH_MSG_KEX_LAST = 49;

    public static final byte SSH_MSG_KEXDH_INIT = 30;
    public static final byte SSH_MSG_KEXDH_REPLY = 31;

    public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
    public static final byte SSH_MSG_KEX_DH_GEX_GROUP = 31;
    public static final byte SSH_MSG_KEX_DH_GEX_INIT = 32;
    public static final byte SSH_MSG_KEX_DH_GEX_REPLY = 33;
    public static final byte SSH_MSG_KEX_DH_GEX_REQUEST = 34;

    public static final byte SSH_MSG_USERAUTH_REQUEST = 50;
    public static final byte SSH_MSG_USERAUTH_FAILURE = 51;
    public static final byte SSH_MSG_USERAUTH_SUCCESS = 52;
    public static final byte SSH_MSG_USERAUTH_BANNER = 53;

    public static final byte SSH_MSG_USERAUTH_INFO_REQUEST = 60;
    public static final byte SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

    public static final byte SSH_MSG_USERAUTH_PK_OK = 60;

    public static final byte SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

    public static final byte SSH_MSG_USERAUTH_GSSAPI_MIC = 66;

    public static final byte SSH_MSG_GLOBAL_REQUEST = 80;
    public static final byte SSH_MSG_REQUEST_SUCCESS = 81;
    public static final byte SSH_MSG_REQUEST_FAILURE = 82;
    public static final byte SSH_MSG_CHANNEL_OPEN = 90;
    public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    public static final byte SSH_MSG_CHANNEL_DATA = 94;
    public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    public static final byte SSH_MSG_CHANNEL_EOF = 96;
    public static final byte SSH_MSG_CHANNEL_CLOSE = 97;
    public static final byte SSH_MSG_CHANNEL_REQUEST = 98;
    public static final byte SSH_MSG_CHANNEL_SUCCESS = 99;
    public static final byte SSH_MSG_CHANNEL_FAILURE = 100;

    //
    // Disconnect error codes
    //
    public static final int SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
    public static final int SSH2_DISCONNECT_PROTOCOL_ERROR = 2;
    public static final int SSH2_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
    public static final int SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED = 4;
    public static final int SSH2_DISCONNECT_RESERVED = 4;
    public static final int SSH2_DISCONNECT_MAC_ERROR = 5;
    public static final int SSH2_DISCONNECT_COMPRESSION_ERROR = 6;
    public static final int SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    public static final int SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    public static final int SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
    public static final int SSH2_DISCONNECT_CONNECTION_LOST = 10;
    public static final int SSH2_DISCONNECT_BY_APPLICATION = 11;
    public static final int SSH2_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
    public static final int SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    public static final int SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    public static final int SSH2_DISCONNECT_ILLEGAL_USER_NAME = 15;

    //
    // Open error codes
    //

    public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int SSH_OPEN_CONNECT_FAILED = 2;
    public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;

    // Some more constants
    public static final int SSH_EXTENDED_DATA_STDERR = 1; // see RFC4254 section 5.2
    // 32-bit length + 8-bit pad length
    public static final int SSH_PACKET_HEADER_LEN = Integer.BYTES + Byte.BYTES;
    /*
     * See https://tools.ietf.org/html/rfc4253#section-6.1:
     *
     * All implementations MUST be able to process packets with an uncompressed payload length of 32768 bytes or less
     * and a total packet size of 35000 bytes or less
     */
    public static final int SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT = 32768;
    public static final int SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT = 35000;

    private SshConstants() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    private static final class LazyAmbiguousOpcodesHolder {
        private static final Set<Integer> AMBIGUOUS_OPCODES = Collections.unmodifiableSet(
                new HashSet<>(
                        LoggingUtils.getAmbiguousMenmonics(SshConstants.class, "SSH_MSG_").values()));

        private LazyAmbiguousOpcodesHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * @param  cmd The command value
     * @return     {@code true} if this value is used by several <U>different</U> messages
     * @see        #getAmbiguousOpcodes()
     */
    public static boolean isAmbiguousOpcode(int cmd) {
        Collection<Integer> ambiguousOpcodes = getAmbiguousOpcodes();
        return ambiguousOpcodes.contains(cmd);
    }

    /**
     * @return A {@link Set} of opcodes that are used by several <U>different</U> messages
     */
    @SuppressWarnings("synthetic-access")
    public static Set<Integer> getAmbiguousOpcodes() {
        return LazyAmbiguousOpcodesHolder.AMBIGUOUS_OPCODES;
    }

    private static final class LazyMessagesMapHolder {
        private static final Map<Integer, String> MESSAGES_MAP = LoggingUtils.generateMnemonicMap(SshConstants.class, f -> {
            String name = f.getName();
            if (!name.startsWith("SSH_MSG_")) {
                return false;
            }

            try {
                return !isAmbiguousOpcode(f.getByte(null));
            } catch (Exception e) {
                return false;
            }
        });

        private LazyMessagesMapHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts a command value to a user-friendly name
     *
     * @param  cmd The command value
     * @return     The user-friendly name - if not one of the defined {@code SSH_MSG_XXX} values then returns the string
     *             representation of the command's value
     */
    public static String getCommandMessageName(int cmd) {
        @SuppressWarnings("synthetic-access")
        String name = LazyMessagesMapHolder.MESSAGES_MAP.get(cmd);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(cmd);
        } else {
            return name;
        }
    }

    private static final class LazyReasonsMapHolder {
        private static final Map<Integer, String> REASONS_MAP
                = LoggingUtils.generateMnemonicMap(SshConstants.class, "SSH2_DISCONNECT_");

        private LazyReasonsMapHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts a disconnect reason value to a user-friendly name
     *
     * @param  reason The disconnect reason value
     * @return        The user-friendly name - if not one of the defined {@code SSH2_DISCONNECT_} values then returns
     *                the string representation of the reason's value
     */
    public static String getDisconnectReasonName(int reason) {
        @SuppressWarnings("synthetic-access")
        String name = LazyReasonsMapHolder.REASONS_MAP.get(reason);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(reason);
        } else {
            return name;
        }
    }

    private static final class LazyOpenCodesMapHolder {
        private static final Map<Integer, String> OPEN_CODES_MAP
                = LoggingUtils.generateMnemonicMap(SshConstants.class, "SSH_OPEN_");

        private LazyOpenCodesMapHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts an open error value to a user-friendly name
     *
     * @param  code The open error value
     * @return      The user-friendly name - if not one of the defined {@code SSH_OPEN_} values then returns the string
     *              representation of the reason's value
     */
    public static String getOpenErrorCodeName(int code) {
        @SuppressWarnings("synthetic-access")
        String name = LazyOpenCodesMapHolder.OPEN_CODES_MAP.get(code);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(code);
        } else {
            return name;
        }
    }
}
