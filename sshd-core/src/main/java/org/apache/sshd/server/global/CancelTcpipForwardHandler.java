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
package org.apache.sshd.server.global;

import java.util.Objects;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * Handler for &quot;cancel-tcpip-forward&quot; global request.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/rfc4254#section-7">RFC4254 section 7</A>
 */
public class CancelTcpipForwardHandler extends AbstractConnectionServiceRequestHandler {
    public static final String REQUEST = "cancel-tcpip-forward";
    /**
     * Default growth factor function used to resize response buffers
     */
    public static final IntUnaryOperator RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.add(Byte.SIZE);

    public static final CancelTcpipForwardHandler INSTANCE = new CancelTcpipForwardHandler();

    public CancelTcpipForwardHandler() {
        super();
    }

    @Override
    public Result process(
            ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
            throws Exception {
        if (!REQUEST.equals(request)) {
            return super.process(connectionService, request, wantReply, buffer);
        }

        String address = buffer.getString();
        int port = buffer.getInt();
        SshdSocketAddress socketAddress = new SshdSocketAddress(address, port);
        if (log.isDebugEnabled()) {
            log.debug("process({})[{}] {} reply={}", connectionService, request, socketAddress, wantReply);
        }

        Forwarder forwarder = Objects.requireNonNull(connectionService.getForwarder(), "No TCP/IP forwarder");
        forwarder.localPortForwardingCancelled(socketAddress);

        if (wantReply) {
            Session session = connectionService.getSession();
            buffer = session.createBuffer(SshConstants.SSH_MSG_REQUEST_SUCCESS, Integer.BYTES);
            buffer.putInt(port);
            session.writePacket(buffer);
        }

        return Result.Replied;
    }
}
