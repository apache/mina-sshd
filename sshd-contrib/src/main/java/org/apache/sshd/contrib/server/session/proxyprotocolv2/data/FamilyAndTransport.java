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

package org.apache.sshd.contrib.server.session.proxyprotocolv2.data;

import java.util.stream.Stream;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.exception.ProxyProtocolException;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;

/**
 * Family and Transport Enumeration.
 * <p>
 * The 14th byte contains the transport protocol and address family. The highest 4 bits contain the address family, the
 * lowest 4 bits contain the protocol.
 * </p>
 * <p>
 * The address family maps to the original socket family without necessarily matching the values internally used by the
 * system. It may be one of : - 0x0 : AF_UNSPEC : the connection is forwarded for an unknown, unspecified or unsupported
 * protocol. The sender should use this family when sending LOCAL commands or when dealing with unsupported protocol
 * families. The receiver is free to accept the connection anyway and use the real endpoint addresses or to reject it.
 * The receiver should ignore address information. - 0x1 : AF_INET : the forwarded connection uses the AF_INET address
 * family (IPv4). The addresses are exactly 4 bytes each in network byte order, followed by transport protocol
 * information (typically ports). - 0x2 : AF_INET6 : the forwarded connection uses the AF_INET6 address family (IPv6).
 * The addresses are exactly 16 bytes each in network byte order, followed by transport protocol information (typically
 * ports). - 0x3 : AF_UNIX : the forwarded connection uses the AF_UNIX address family (UNIX). The addresses are exactly
 * 108 bytes each. - other values are unspecified and must not be emitted in version 2 of this protocol and must be
 * rejected as invalid by receivers.
 * </p>
 * <p>
 * The transport protocol is specified in the lowest 4 bits of the 14th byte : - 0x0 : UNSPEC : the connection is
 * forwarded for an unknown, unspecified or unsupported protocol. The sender should use this family when sending LOCAL
 * commands or when dealing with unsupported protocol families. The receiver is free to accept the connection anyway and
 * use the real endpoint addresses or to reject it. The receiver should ignore address information. - 0x1 : STREAM : the
 * forwarded connection uses a SOCK_STREAM protocol (eg: TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the
 * addresses are followed by the source and destination ports represented on 2 bytes each in network byte order. - 0x2 :
 * DGRAM : the forwarded connection uses a SOCK_DGRAM protocol (eg: UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6
 * (UDP), the addresses are followed by the source and destination ports represented on 2 bytes each in network byte
 * order. - other values are unspecified and must not be emitted in version 2 of this protocol and must be rejected as
 * invalid by receivers.
 * </p>
 * <p>
 * In practice, the following protocol bytes are expected : - \x00 : UNSPEC : the connection is forwarded for an
 * unknown, unspecified or unsupported protocol. The sender should use this family when sending LOCAL commands or when
 * dealing with unsupported protocol families. When used with a LOCAL command, the receiver must accept the connection
 * and ignore any address information. For other commands, the receiver is free to accept the connection anyway and use
 * the real endpoints addresses or to reject the connection. The receiver should ignore address information. - \x11 :
 * TCP over IPv4 : the forwarded connection uses TCP over the AF_INET protocol family. Address length is 2*4 + 2*2 = 12
 * bytes. - \x12 : UDP over IPv4 : the forwarded connection uses UDP over the AF_INET protocol family. Address length is
 * 2*4 + 2*2 = 12 bytes. - \x21 : TCP over IPv6 : the forwarded connection uses TCP over the AF_INET6 protocol family.
 * Address length is 2*16 + 2*2 = 36 bytes. - \x22 : UDP over IPv6 : the forwarded connection uses UDP over the AF_INET6
 * protocol family. Address length is 2*16 + 2*2 = 36 bytes. - \x31 : UNIX stream : the forwarded connection uses
 * SOCK_STREAM over the AF_UNIX protocol family. Address length is 2*108 = 216 bytes. - \x32 : UNIX datagram : the
 * forwarded connection uses SOCK_DGRAM over the AF_UNIX protocol family. Address length is 2*108 = 216 bytes.
 * </p>
 * <p>
 * Only the UNSPEC protocol byte (\x00) is mandatory to implement on the receiver. A receiver is not required to
 * implement other ones, provided that it automatically falls back to the UNSPEC mode for the valid combinations above
 * that it does not support.
 * </p>
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public enum FamilyAndTransport {

    UNSPEC((byte) 0x00, 0, 0),
    TCP4((byte) 0x11, 4, 2),
    UDP4((byte) 0x12, 4, 2),
    TCP6((byte) 0x21, 16, 2),
    UDP6((byte) 0x22, 16, 2),
    SOCK_STREAM((byte) 0x31, 108, 0),
    SOCK_DGRAM((byte) 0x32, 108, 0);

    private final byte value;

    private final int addressLength;

    private final int portLength;

    FamilyAndTransport(byte value, int addressLength, int portLength) {
        this.value = value;
        this.addressLength = addressLength;
        this.portLength = portLength;
    }

    public static FamilyAndTransport extractValue(Logger logger, ServerSession session, Buffer buffer)
            throws ProxyProtocolException {
        byte value = buffer.getByte();
        return Stream.of(values())
                .filter(val -> val.value == value)
                .findFirst()
                .orElseThrow(() -> ProxyProtocolException.buildFamilyAndTransport(logger, session, value));
    }

    public int getAddressLength() {
        return addressLength;
    }

    public int getDataLength() {
        return addressLength * 2 + portLength * 2;
    }

    public boolean hasInetAddress() {
        return addressLength > 0 && portLength > 0;
    }

    public boolean hasPort() {
        return portLength > 0;
    }

    public boolean hasSockAddress() {
        return addressLength > 0 && portLength == 0;
    }
}
