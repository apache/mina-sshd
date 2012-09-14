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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.net.Socket;

import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.ForwardingAcceptorFactory;
import org.apache.sshd.common.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Default factory for creating NioSocketAcceptors for Port & X11 Forwarding
 */
public class DefaultForwardingAcceptorFactory implements ForwardingAcceptorFactory {

    /** The log. */
    private final Logger log = LoggerFactory.getLogger(getClass());

    public NioSocketAcceptor createNioSocketAcceptor(Session s) {
        NioSocketAcceptor nio = new NioSocketAcceptor();
        nio.setReuseAddress(true);

        configureReceiveBufferSize(nio);

        return nio;
    }

    /**
     * MINA itself forces our socket receive buffer to 1024 bytes by default,
     * despite what the operating system defaults to. This limits us to about 3
     * MB/s incoming data transfer. By forcing back to the operating system
     * default we can get a decent transfer rate again.
     * 
     * If this method is unable to adjust the buffer size it will log a warning
     * and return.
     * 
     * @param nio
     *            The NioSocketAcceptor to fix the buffer on
     */
    private void configureReceiveBufferSize(NioSocketAcceptor nio) {
        final Socket s = new Socket();
        try {
            try {
                nio.getSessionConfig().setReceiveBufferSize(
                        s.getReceiveBufferSize());
            } finally {
                s.close();
            }
        } catch (IOException e) {
            log.warn("cannot adjust SO_RCVBUF back to system default", e);
        }
    }

}
