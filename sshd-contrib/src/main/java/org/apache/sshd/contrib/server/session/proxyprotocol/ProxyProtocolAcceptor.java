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

package org.apache.sshd.contrib.server.session.proxyprotocol;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.AbstractServerSession;
import org.apache.sshd.server.session.ServerProxyAcceptor;
import org.apache.sshd.server.session.ServerSession;

/**
 * A working prototype to support PROXY protocol as described in
 * <A HREF="http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt">HAProxy Documentation</A>.
 *
 * @see    <A HREF="https://gist.github.com/codingtony/a8684c9ffa08ad56899f94d3b6c2a040">Tony Bussieres contribution</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProxyProtocolAcceptor extends AbstractLoggingBean implements ServerProxyAcceptor {
    // 108 bytes is the largest buffer needed for the PROXY protocol, but we are a bit more lenient
    public static final int MAX_PROXY_HEADER_LENGTH = Byte.MAX_VALUE;
    public static final String PROX_PROTOCOL_PREFIX = "PROXY";

    private static final byte[] PROXY_HEADER = new byte[] { 0x50, 0x52, 0x4F, 0x58, 0x59, 0x20 };

    public ProxyProtocolAcceptor() {
        super();
    }

    @Override
    public boolean acceptServerProxyMetadata(ServerSession session, Buffer buffer) throws Exception {
        int mark = buffer.rpos();
        int dataLen = buffer.available();
        if (dataLen < PROXY_HEADER.length) {
            if (log.isDebugEnabled()) {
                log.debug("acceptServerProxyMetadata(session={}) incomplete data - {}/{}", session, dataLen,
                        PROXY_HEADER.length);
            }
            return false;
        }

        byte[] proxyHeader = new byte[PROXY_HEADER.length];
        buffer.getRawBytes(proxyHeader);
        buffer.rpos(mark); // Rewind the buffer

        if (!Arrays.equals(PROXY_HEADER, proxyHeader)) {
            if (log.isDebugEnabled()) {
                log.debug("acceptServerProxyMetadata(session={}) mismatched protocol header: expected={}, actual={}",
                        session, BufferUtils.toHex(':', PROXY_HEADER), BufferUtils.toHex(':', proxyHeader));
            }
            return true;
        }

        StringBuilder proxyPayload = new StringBuilder(MAX_PROXY_HEADER_LENGTH);
        while ((proxyPayload.length() < MAX_PROXY_HEADER_LENGTH) && (buffer.available() > 0)) {
            char ch = (char) buffer.getUByte();
            if (ch != '\n') {
                proxyPayload.append(ch);
                continue;
            }

            // remove trailing CR if found
            int ppLen = proxyPayload.length();
            if ((ppLen > 0) && (proxyPayload.charAt(ppLen - 1) == '\r')) {
                proxyPayload.setLength(ppLen - 1);
            }

            return parseProxyHeader(session, proxyPayload.toString(), mark, buffer);
        }

        // Could not see LF before MAX_PROXY_HEADER_LENGTH expired
        buffer.rpos(mark); // Rewind the buffer
        return false;
    }

    protected boolean parseProxyHeader(ServerSession session, String proxyHeader, int markPosition, Buffer buffer)
            throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("parseProxyHeader(session={}) parsing header='{}'", session, proxyHeader);
        }

        String[] proxyFields = GenericUtils.split(proxyHeader, ' ');
        // Trim all fields just in case more than one space used
        for (int index = 0; index < proxyFields.length; index++) {
            String f = proxyFields[index];
            proxyFields[index] = GenericUtils.trimToEmpty(f);
        }

        String proxyProtocolPrefix = proxyFields[0];
        ValidateUtils.checkTrue(PROX_PROTOCOL_PREFIX.equalsIgnoreCase(proxyProtocolPrefix), "Mismatched protocol prefix: %s",
                proxyProtocolPrefix);

        String protocolVersion = proxyFields[1];
        if ("TCP4".equalsIgnoreCase(protocolVersion) || "TCP6".equalsIgnoreCase(protocolVersion)) {
            String layer3SrcAddress = proxyFields[2];
            String layer3DstAddress = proxyFields[3];
            String layer3SrcPort = proxyFields[4];
            String layer3DstPort = proxyFields[5];
            if (debugEnabled) {
                log.debug("parseProxyHeader(session={}) using {}:{} -> {}:{} proxy",
                        session, layer3SrcAddress, layer3SrcPort, layer3DstAddress, layer3DstPort);
            }

            if (session instanceof AbstractServerSession) {
                // Set the client address in the session from the proxy payload
                InetSocketAddress clientAddress = new InetSocketAddress(layer3SrcAddress, Integer.parseInt(layer3SrcPort));
                ((AbstractServerSession) session).setClientAddress(clientAddress);
            }
        } else {
            log.warn("parseProxyHeader(session={}) unsuppored sub-protocol - {} - continue as usual", session, protocolVersion);
        }

        return true;
    }
}
