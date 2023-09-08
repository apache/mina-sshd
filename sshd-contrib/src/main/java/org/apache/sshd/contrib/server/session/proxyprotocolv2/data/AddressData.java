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

import java.io.IOException;
import java.net.InetAddress;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.utils.ProxyUtils;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;

/**
 * Address data structure.
 * <p>
 * Starting from the 17th byte, addresses are presented in network byte order.
 * </p>
 * <p>
 * The address order is always the same : - source layer 3 address in network byte order - destination layer 3 address
 * in network byte order - source layer 4 address if any, in network byte order (port) - destination layer 4 address if
 * any, in network byte order (port)
 * </p>
 * <p>
 * The address block may directly be sent from or received into the following union which makes it easy to cast from/to
 * the relevant socket native structs depending on the address type :
 * </p>
 *
 * <pre>
 *     union proxy_addr {
 *         struct {        // for TCP/UDP over IPv4, len = 12
 *             uint32_t src_addr;
 *             uint32_t dst_addr;
 *             uint16_t src_port;
 *             uint16_t dst_port;
 *         }ipv4_addr;
 *         struct{        // for TCP/UDP over IPv6, len = 36
 *             uint8_t src_addr[16];
 *             uint8_t dst_addr[16];
 *             uint16_t src_port;
 *             uint16_t dst_port;
 *         }ipv6_addr;
 *         struct{        // for AF_UNIX sockets, len = 216
 *             uint8_t src_addr[108];
 *             uint8_t dst_addr[108];
 *         }unix_addr;
 *     };
 * </pre>
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public final class AddressData {

    private final String srcAddress;
    private final String dstAddress;

    private final int srcPort;
    private final int dstPort;

    private AddressData(String srcAddress, String dstAddress, int srcPort, int dstPort) {
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
    }

    public static AddressData extractAddressData(
            Logger logger,
            ServerSession session,
            Buffer buffer,
            FamilyAndTransport familyAndTransport,
            int dataLength)
            throws IOException {
        String srcAddress = extractAddresses(buffer, familyAndTransport);
        String dstAddress = extractAddresses(buffer, familyAndTransport);
        int srcPort = extractPort(buffer, familyAndTransport);
        int dstPort = extractPort(buffer, familyAndTransport);
        skipUnprocessedData(logger, session, buffer, familyAndTransport, dataLength);
        return new AddressData(srcAddress, dstAddress, srcPort, dstPort);
    }

    public static void skipUnprocessedData(
            Logger logger,
            ServerSession session,
            Buffer buffer,
            FamilyAndTransport familyAndTransport,
            int dataLength) {
        int remaining = dataLength - familyAndTransport.getDataLength();
        if (remaining > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("extractAddressData({}) skipping additional datas [{}]",
                        session,
                        ProxyUtils.toHexString(buffer, buffer.rpos()));
            }
            // Insure the remaining bytes are available
            buffer.ensureAvailable(remaining);
            // Skip all extra datas
            buffer.rpos(buffer.rpos() + remaining);
        }
    }

    private static String extractAddresses(Buffer buffer, FamilyAndTransport familyAndTransport)
            throws IOException {
        byte[] datas = new byte[familyAndTransport.getAddressLength()];
        buffer.getRawBytes(datas);
        if (familyAndTransport.hasInetAddress()) {
            return InetAddress.getByAddress(datas).getHostAddress();
        }
        return "";
    }

    private static int extractPort(Buffer buffer, FamilyAndTransport familyAndTransport) {
        if (familyAndTransport.hasPort()) {
            return buffer.getUShort();
        }
        return 0;
    }

    @Override
    public String toString() {
        return String.join(" ", srcAddress, dstAddress, Integer.toString(srcPort), Integer.toString(dstPort));
    }
}
