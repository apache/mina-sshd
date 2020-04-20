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
package org.apache.sshd.server.forward;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * Determines if a forwarding request will be permitted.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ForwardingFilter extends AgentForwardingFilter, X11ForwardingFilter, TcpForwardingFilter {
    /**
     * Wraps separate filtering policies into one - any {@code null} one is assumed to be disabled
     *
     * @param  agentFilter The {@link AgentForwardingFilter}
     * @param  x11Filter   The {@link X11ForwardingFilter}
     * @param  tcpFilter   The {@link TcpForwardingFilter}
     * @return             The combined implementation
     */
    static ForwardingFilter asForwardingFilter(
            AgentForwardingFilter agentFilter, X11ForwardingFilter x11Filter, TcpForwardingFilter tcpFilter) {
        if ((agentFilter == null) && (x11Filter == null) && (tcpFilter == null)) {
            return RejectAllForwardingFilter.INSTANCE;
        }

        return new ForwardingFilter() {
            @Override
            public boolean canForwardAgent(Session session, String requestType) {
                return (agentFilter != null) && agentFilter.canForwardAgent(session, requestType);
            }

            @Override
            public boolean canForwardX11(Session session, String requestType) {
                return (x11Filter != null) && x11Filter.canForwardX11(session, requestType);
            }

            @Override
            public boolean canListen(SshdSocketAddress address, Session session) {
                return (tcpFilter != null) && tcpFilter.canListen(address, session);
            }

            @Override
            public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
                return (tcpFilter != null) && tcpFilter.canConnect(type, address, session);
            }
        };
    }
}
