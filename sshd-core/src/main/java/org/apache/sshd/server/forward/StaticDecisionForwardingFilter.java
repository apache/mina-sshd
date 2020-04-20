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
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * A {@link ForwardingFilter} implementation that returns the same &quot;static&quot; result for <U>all</U> the queries.
 */
public class StaticDecisionForwardingFilter extends AbstractLoggingBean implements ForwardingFilter {
    private final boolean acceptance;

    /**
     * @param acceptance The acceptance status for <U>all</U> the queries
     */
    public StaticDecisionForwardingFilter(boolean acceptance) {
        this.acceptance = acceptance;
    }

    public final boolean isAccepted() {
        return acceptance;
    }

    @Override
    public boolean canForwardAgent(Session session, String requestType) {
        return checkAcceptance(requestType, session, SshdSocketAddress.LOCALHOST_ADDRESS);
    }

    @Override
    public boolean canForwardX11(Session session, String requestType) {
        return checkAcceptance(requestType, session, SshdSocketAddress.LOCALHOST_ADDRESS);
    }

    @Override
    public boolean canListen(SshdSocketAddress address, Session session) {
        return checkAcceptance("tcpip-forward", session, address);
    }

    @Override
    public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
        return checkAcceptance(type.getName(), session, address);
    }

    /**
     * @param  request The SSH request that ultimately led to this filter being consulted
     * @param  session The requesting {@link Session}
     * @param  target  The request target - may be {@link SshdSocketAddress#LOCALHOST_ADDRESS} if no real target
     * @return         The (static) {@link #isAccepted()} flag
     */
    protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
        boolean accepted = isAccepted();
        if (log.isDebugEnabled()) {
            log.debug("checkAcceptance(" + request + ")[" + session + "] acceptance for target=" + target + " is " + accepted);
        }
        return accepted;
    }
}
