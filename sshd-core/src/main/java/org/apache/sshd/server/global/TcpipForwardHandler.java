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

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.forward.TcpipForwarder;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * Handler for tcpip-forward global request.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipForwardHandler extends AbstractConnectionServiceRequestHandler {
    public static final String REQUEST = "tcpip-forward";

    /**
     * Default growth factor function used to resize response buffers
     */
    public static final Int2IntFunction RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.Utils.add(Byte.SIZE);

    public static final TcpipForwardHandler INSTANCE = new TcpipForwardHandler();

    public TcpipForwardHandler() {
        super();
    }

    @Override
    public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer) throws Exception {
        if (!REQUEST.equals(request)) {
            return super.process(connectionService, request, wantReply, buffer);
        }

        String address = buffer.getString();
        int port = buffer.getInt();
        SshdSocketAddress socketAddress = new SshdSocketAddress(address, port);
        TcpipForwarder forwarder = ValidateUtils.checkNotNull(connectionService.getTcpipForwarder(), "No TCP/IP forwader");
        SshdSocketAddress bound = forwarder.localPortForwardingRequested(socketAddress);
        if (log.isDebugEnabled()) {
            log.debug("process({})[{}][want-reply-{}] {} => {}",
                      connectionService, request, wantReply, socketAddress, bound);
        }

        if (bound == null) {
            return Result.ReplyFailure;
        }

        port = bound.getPort();
        if (wantReply) {
            Session session = connectionService.getSession();
            buffer = session.createBuffer(SshConstants.SSH_MSG_REQUEST_SUCCESS, Integer.SIZE / Byte.SIZE);
            buffer.putInt(port);
            session.writePacket(buffer);
        }

        return Result.Replied;
    }
}
