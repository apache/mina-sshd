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
 * Version and command enumeration.
 * <p>
 * The 13th byte is the protocol version and command. The highest four bits contains the version. As of this
 * specification, it must always be sent as \x2 and the receiver must only accept this value.
 * </p>
 * <p>
 * The lowest four bits represents the command : - \x0 : LOCAL : the connection was established on purpose by the proxy
 * without being relayed. The connection endpoints are the sender and the receiver. Such connections exist when the
 * proxy sends health-checks to the server. The receiver must accept this connection as valid and must use the real
 * connection endpoints and discard the protocol block including the family which is ignored. - \x1 : PROXY : the
 * connection was established on behalf of another node, and reflects the original connection endpoints. The receiver
 * must then use the information provided in the protocol block to get original the address. - other values are
 * unassigned and must not be emitted by senders. Receivers must drop connections presenting unexpected values here.
 * </p>
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public enum VersionAndCommand {

    LOCAL((byte) 0x20),
    PROXY((byte) 0x21);

    private final byte value;

    VersionAndCommand(byte value) {
        this.value = value;
    }

    public static VersionAndCommand extractValue(Logger logger, ServerSession session, Buffer buffer)
            throws ProxyProtocolException {
        byte value = buffer.getByte();
        return Stream.of(values())
                .filter(val -> val.value == value)
                .findFirst()
                .orElseThrow(() -> ProxyProtocolException.buildVersionOrCommand(logger, session, value));
    }
}
