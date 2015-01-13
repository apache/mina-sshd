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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This interface defines constants for the SSH protocol.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SshConstants {

    //
    // SSH message identifiers
    //

    static final byte SSH_MSG_DISCONNECT=                      1;
    static final byte SSH_MSG_IGNORE=                          2;
    static final byte SSH_MSG_UNIMPLEMENTED=                   3;
    static final byte SSH_MSG_DEBUG=                           4;
    static final byte SSH_MSG_SERVICE_REQUEST=                 5;
    static final byte SSH_MSG_SERVICE_ACCEPT=                  6;
    static final byte SSH_MSG_KEXINIT=                        20;
    static final byte SSH_MSG_NEWKEYS=                        21;

    static final byte SSH_MSG_KEX_FIRST=                      30;
    static final byte SSH_MSG_KEX_LAST=                       49;

    static final byte SSH_MSG_KEXDH_INIT=                     30;
    static final byte SSH_MSG_KEXDH_REPLY=                    31;

    static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD=         30;
    static final byte SSH_MSG_KEX_DH_GEX_GROUP=               31;
    static final byte SSH_MSG_KEX_DH_GEX_INIT=                32;
    static final byte SSH_MSG_KEX_DH_GEX_REPLY=               33;
    static final byte SSH_MSG_KEX_DH_GEX_REQUEST=             34;

    static final byte SSH_MSG_USERAUTH_REQUEST=               50;
    static final byte SSH_MSG_USERAUTH_FAILURE=               51;
    static final byte SSH_MSG_USERAUTH_SUCCESS=               52;
    static final byte SSH_MSG_USERAUTH_BANNER=                53;

    static final byte SSH_MSG_USERAUTH_INFO_REQUEST=          60;
    static final byte SSH_MSG_USERAUTH_INFO_RESPONSE=         61;

    static final byte SSH_MSG_USERAUTH_PK_OK=                 60;

    static final byte SSH_MSG_USERAUTH_PASSWD_CHANGEREQ=      60;

    static final byte SSH_MSG_USERAUTH_GSSAPI_MIC=            66;

    static final byte SSH_MSG_GLOBAL_REQUEST=                 80;
    static final byte SSH_MSG_REQUEST_SUCCESS=                81;
    static final byte SSH_MSG_REQUEST_FAILURE=                82;
    static final byte SSH_MSG_CHANNEL_OPEN=                   90;
    static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION=      91;
    static final byte SSH_MSG_CHANNEL_OPEN_FAILURE=           92;
    static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST=          93;
    static final byte SSH_MSG_CHANNEL_DATA=                   94;
    static final byte SSH_MSG_CHANNEL_EXTENDED_DATA=          95;
    static final byte SSH_MSG_CHANNEL_EOF=                    96;
    static final byte SSH_MSG_CHANNEL_CLOSE=                  97;
    static final byte SSH_MSG_CHANNEL_REQUEST=                98;
    static final byte SSH_MSG_CHANNEL_SUCCESS=                99;
    static final byte SSH_MSG_CHANNEL_FAILURE=               100;

    //
    // Values for the algorithms negotiation
    //

    static final int PROPOSAL_KEX_ALGS = 0;
    static final int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;
    static final int PROPOSAL_ENC_ALGS_CTOS = 2;
    static final int PROPOSAL_ENC_ALGS_STOC = 3;
    static final int PROPOSAL_MAC_ALGS_CTOS = 4;
    static final int PROPOSAL_MAC_ALGS_STOC = 5;
    static final int PROPOSAL_COMP_ALGS_CTOS = 6;
    static final int PROPOSAL_COMP_ALGS_STOC = 7;
    static final int PROPOSAL_LANG_CTOS = 8;
    static final int PROPOSAL_LANG_STOC = 9;
    static final int PROPOSAL_MAX = 10;

    /**
     * User-friendly names for the KEX algorithms negotiation items - the
     * list index matches the {@code PROPOSAL_XXX} constant
     * @see <A HREF="http://tools.ietf.org/html/rfc4253#section-7.1">RFC-4253 - section 7.1</A>
     */
    static final String[] PROPOSAL_KEX_NAMES = {
            "kex algorithms",
            "server host key algorithms",
            "encryption algorithms (client to server)",
            "encryption algorithms (server to client)",
            "mac algorithms (client to server)",
            "mac algorithms (server to client)",
            "compression algorithms (client to server)",
            "compression algorithms (server to client)",
            "languages (client to server)",
            "languages (server to client)"
    };


    //
    // Disconnect error codes
    //
    static final int SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT =     1;
    static final int SSH2_DISCONNECT_PROTOCOL_ERROR =                  2;
    static final int SSH2_DISCONNECT_KEY_EXCHANGE_FAILED =             3;
    static final int SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED =      4;
    static final int SSH2_DISCONNECT_RESERVED =                        4;
    static final int SSH2_DISCONNECT_MAC_ERROR =                       5;
    static final int SSH2_DISCONNECT_COMPRESSION_ERROR =               6;
    static final int SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE =           7;
    static final int SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED =  8;
    static final int SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE =         9;
    static final int SSH2_DISCONNECT_CONNECTION_LOST =                10;
    static final int SSH2_DISCONNECT_BY_APPLICATION =                 11;
    static final int SSH2_DISCONNECT_TOO_MANY_CONNECTIONS =           12;
    static final int SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER =         13;
    static final int SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    static final int SSH2_DISCONNECT_ILLEGAL_USER_NAME =              15;

    //
    // Open error codes
    //

    static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED=     1;
    static final int SSH_OPEN_CONNECT_FAILED=                  2;
    static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE=            3;
    static final int SSH_OPEN_RESOURCE_SHORTAGE=               4;

}
