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

package org.apache.sshd.cli.server.helper;

import java.io.IOException;

import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.slf4j.Logger;

public class ServerPortForwardingEventListener extends ServerEventListenerHelper implements PortForwardingEventListener {
    public ServerPortForwardingEventListener(Logger logger) {
        super("PORT-FWD", logger);
    }

    @Override
    public void establishedExplicitTunnel(
            Session session, SshdSocketAddress local, SshdSocketAddress remote,
            boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        if (reason == null) {
            if (log.isInfoEnabled()) {
                log.info("Estalibshed explicit tunnel for session={}: local={}, remote={}, bound={}, localForward={}",
                        session, local, remote, boundAddress, localForwarding);
            }
        } else {
            log.error(
                    "Failed ({}) to establish explicit tunnel for session={}, local={}, remote={}, bound={}, localForward={}: {}",
                    reason.getClass().getSimpleName(), session, local, remote, boundAddress, localForwarding,
                    reason.getMessage());
        }
    }

    @Override
    public void tornDownExplicitTunnel(
            Session session, SshdSocketAddress address, boolean localForwarding, SshdSocketAddress remoteAddress,
            Throwable reason)
            throws IOException {
        if (reason == null) {
            if (log.isInfoEnabled()) {
                log.info("Torn down explicit tunnel for session={}: address={}, remote={}, localForward={}",
                        session, address, remoteAddress, localForwarding);
            }
        } else {
            log.error(
                    "Failed ({}) to tear down explicit tunnel for session={}, address={}, remote={}, localForward={}: {}",
                    reason.getClass().getSimpleName(), session, address, remoteAddress, localForwarding, reason.getMessage());
        }
    }

    @Override
    public void establishedDynamicTunnel(
            Session session, SshdSocketAddress local, SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        if (reason == null) {
            if (log.isInfoEnabled()) {
                log.info("Estalibshed dynamic tunnel for session={}: local={},  bound={}", session, local, boundAddress);
            }
        } else {
            log.error("Failed ({}) to establish dynamic tunnel for session={}, bound={}: {}",
                    reason.getClass().getSimpleName(), session, local, boundAddress, reason.getMessage());
        }
    }

    @Override
    public void tornDownDynamicTunnel(
            Session session, SshdSocketAddress address, Throwable reason)
            throws IOException {
        if (reason == null) {
            if (log.isInfoEnabled()) {
                log.info("Torn down dynamic tunnel for session={}: address={}", session);
            }
        } else {
            log.error("Failed ({}) to tear down dynamic tunnel for session={}, address={}: {}",
                    reason.getClass().getSimpleName(), session, address, reason.getMessage());
        }
    }
}
