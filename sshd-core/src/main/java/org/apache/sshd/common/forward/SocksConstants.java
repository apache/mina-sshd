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
package org.apache.sshd.common.forward;

/**
 * SOCKS constants.
 */
public final class SocksConstants {

    public static final class Socks4 {

        public static final byte VERSION = 4;

        public static final byte CMD_CONNECT = 1;

        public static final byte REPLY_SUCCESS = (byte) 90;

        public static final byte REPLY_FAILURE = (byte) 91;

        public static final byte REPLY_HOST_UNREACHABLE = (byte) 92;

        public static final byte REPLY_WRONG_USER = (byte) 93;

        private Socks4() {
            // No instantiation
        }
    }

    public static final class Socks5 {

        public static final byte VERSION = 5;

        public static final byte CMD_CONNECT = 1;
        // BIND = 2, UPD_ASSOCIATE = 3

        // Address types

        public static final byte ADDRESS_IPV4 = 1;

        public static final byte ADDRESS_FQDN = 3;

        public static final byte ADDRESS_IPV6 = 4;

        // Reply codes

        public static final byte REPLY_SUCCESS = 0;

        public static final byte REPLY_FAILURE = 1;

        public static final byte REPLY_FORBIDDEN = 2;

        public static final byte REPLY_NETWORK_UNREACHABLE = 3;

        public static final byte REPLY_HOST_UNREACHABLE = 4;

        public static final byte REPLY_CONNECTION_REFUSED = 5;

        public static final byte REPLY_TTL_EXPIRED = 6;

        public static final byte REPLY_COMMAND_UNSUPPORTED = 7;

        public static final byte REPLY_ADDRESS_UNSUPPORTED = 8;

        private Socks5() {
            // No instantiation
        }
    }

    private SocksConstants() {
        // No instatiation
    }
}
