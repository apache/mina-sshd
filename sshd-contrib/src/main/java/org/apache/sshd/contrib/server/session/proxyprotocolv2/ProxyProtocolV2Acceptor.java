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

package org.apache.sshd.contrib.server.session.proxyprotocolv2;

import java.util.Arrays;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.contrib.server.session.proxyprotocol.ProxyProtocolAcceptor;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.data.AddressData;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.data.FamilyAndTransport;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.data.VersionAndCommand;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.utils.ProxyUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * A working prototype to support PROXY protocol v2 as described in
 * <A HREF="https://www.haproxy.org/download/2.7/doc/proxy-protocol.txt">HAProxy Documentation</A>.
 * <p>
 * This <code>ServerProxyAcceptor</code> can process PROXY protocol v1 and v2.
 * </p>
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public class ProxyProtocolV2Acceptor extends ProxyProtocolAcceptor {

    // CR LF CR LF NUL CR LF 'Q' 'U' 'I' 'T' LF
    private static final byte[] PROXY_V2_HEADER
            = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

    // Minimum protocol V2 header length: the magic header (12 bytes), a version byte, a protocol byte, and a two-byte
    // MSB-first unsigned short.
    private static final int MIN_HEADER_LENGTH = PROXY_V2_HEADER.length + 4;

    private static final char FIELD_SEPARATOR = ' ';

    public ProxyProtocolV2Acceptor() {
        super();
    }

    @Override
    public boolean acceptServerProxyMetadata(ServerSession session, Buffer buffer) throws Exception {
        int mark = buffer.rpos();
        int dataLen = buffer.available();
        if (dataLen < MIN_HEADER_LENGTH) {
            if (log.isDebugEnabled()) {
                log.debug("acceptServerProxyMetadata(session={}) incomplete data - {}/{}", session, dataLen,
                        MIN_HEADER_LENGTH);
            }
            return false;
        }

        byte[] proxyV2Header = new byte[PROXY_V2_HEADER.length];
        buffer.getRawBytes(proxyV2Header);

        if (!Arrays.equals(PROXY_V2_HEADER, proxyV2Header)) {
            buffer.rpos(mark); // Rewind the buffer to allow further reading
            return super.acceptServerProxyMetadata(session, buffer);
        }
        return readProxyV2Header(session, mark, buffer);
    }

    protected boolean readProxyV2Header(ServerSession session, int markPosition, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            int mark = buffer.rpos();
            buffer.rpos(markPosition);
            log.debug("readProxyV2Header(session={}) processing Proxy Protocol V2 buffer : [{}]", session,
                    ProxyUtils.toHexString(buffer, mark));
        }
        StringBuilder proxyPayload = new StringBuilder();
        // Read the version and command information
        VersionAndCommand versionAndCommand = VersionAndCommand.extractValue(log, session, buffer);
        proxyPayload.append(versionAndCommand.name());
        // Read the family and transport.
        FamilyAndTransport familyAndTransport = FamilyAndTransport.extractValue(log, session, buffer);
        proxyPayload.append(FIELD_SEPARATOR).append(familyAndTransport.name());
        // Read the data length
        int dataLength = buffer.getUShort();
        if (dataLength > buffer.available()) {
            if (log.isDebugEnabled()) {
                log.debug("readProxyV2Header(session={}) incomplete data after header - {}/{}", session, buffer.available(),
                        dataLength);
            }
            buffer.rpos(markPosition);
            return false;
        }
        // Unix Socket are not supported by SSHD
        if (familyAndTransport.hasSockAddress()) {
            log.warn("readProxyV2Header(session={}) unsupported sub-protocol - {} - continue as usual", session,
                    familyAndTransport);
            // Skip socket address data
            AddressData.skipUnprocessedData(log, session, buffer, FamilyAndTransport.UNSPEC, dataLength);
            return true;
        }
        // Read the address Data (Host and Port for source and dest)
        AddressData data = AddressData.extractAddressData(log, session, buffer, familyAndTransport, dataLength);
        proxyPayload.append(FIELD_SEPARATOR).append(data);
        // Parse the converted proxy header
        return parseProxyHeader(session, proxyPayload.toString());
    }

    @Override
    protected boolean parseProxyHeader(ServerSession session, String proxyHeader) {
        String[] proxyFields = GenericUtils.split(proxyHeader, FIELD_SEPARATOR);
        // Trim all fields just in case more than one space used
        for (int index = 0; index < proxyFields.length; index++) {
            String f = proxyFields[index];
            proxyFields[index] = GenericUtils.trimToEmpty(f);
        }
        // Nothing to do for local proxy protocol
        if ("LOCAL".equals(proxyFields[0])) {
            log.debug("parseProxyHeader(session={}) local proxy check", session);
            return true;
        }
        return super.parseProxyHeader(session, proxyHeader);
    }
}
