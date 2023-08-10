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

package org.apache.sshd.contrib.server.session.proxyprotocolv2.exception;

import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;

/**
 * Blocking Exception that must block the connection.
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public final class ProxyProtocolException extends Exception {

    public static final int PROXY_PROTOCOL_VERSION_2 = 2;

    private static final int MAX_FAMILY_CODE = 3;

    private static final long serialVersionUID = -7349477687125144605L;

    private ProxyProtocolException(String message) {
        super(message);
    }

    public static ProxyProtocolException buildVersionOrCommand(Logger log, ServerSession session, byte value) {
        byte valueLow = (byte) (value & 0x0F);
        byte valueHeight = (byte) (value >> 4);
        if (valueHeight != PROXY_PROTOCOL_VERSION_2) {
            if (log.isDebugEnabled()) {
                log.debug("readProxyV2Header(session={}) mismatched version in proxy header: expected={}, actual={}",
                        session,
                        Integer.toHexString(PROXY_PROTOCOL_VERSION_2),
                        Integer.toHexString(valueHeight));
            }
            return new ProxyProtocolException("Invalid version " + valueHeight);
        }
        if (log.isDebugEnabled()) {
            log.debug("readProxyV2Header(session={}) unassigned command in proxy header: actual={}",
                    session, Integer.toHexString(valueLow));
        }
        return new ProxyProtocolException("Unassigned command " + valueLow);
    }

    public static ProxyProtocolException buildFamilyAndTransport(Logger log, ServerSession session, byte value) {
        byte valueLow = (byte) (value & 0x0F);
        byte valueHeight = (byte) (value >> 4);
        if (valueHeight > MAX_FAMILY_CODE) {
            if (log.isDebugEnabled()) {
                log.debug("readProxyV2Header(session={}) unspecified family in proxy header: actual={}",
                        session, Integer.toHexString(valueHeight));
            }
            return new ProxyProtocolException("Unspecified family " + valueHeight);
        }
        if (log.isDebugEnabled()) {
            log.debug("readProxyV2Header(session={}) unspecified transport in proxy header: actual={}",
                    session, Integer.toHexString(valueLow));
        }
        return new ProxyProtocolException("Unspecified transport " + valueLow);
    }
}
