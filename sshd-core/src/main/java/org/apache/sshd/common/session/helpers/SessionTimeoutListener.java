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
package org.apache.sshd.common.session.helpers;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Task that iterates over all currently open {@link Session}s and checks each of them for timeouts. If the
 * {@link AbstractSession} has timed out (either authentication or idle timeout), the session will be disconnected.
 *
 * @see SessionHelper#checkForTimeouts()
 */
public class SessionTimeoutListener
        extends AbstractLoggingBean
        implements SessionListener, Runnable {
    protected final Set<SessionHelper> sessions = new CopyOnWriteArraySet<>();

    public SessionTimeoutListener() {
        super();
    }

    @Override
    public void sessionCreated(Session session) {
        if ((session instanceof SessionHelper)
                && (GenericUtils.isPositive(session.getAuthTimeout()) || GenericUtils.isPositive(session.getIdleTimeout()))) {
            sessions.add((SessionHelper) session);
            if (log.isDebugEnabled()) {
                log.debug("sessionCreated({}) tracking", session);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("sessionCreated({}) not tracked", session);
            }
        }
    }

    @Override
    public void sessionException(Session session, Throwable t) {
        debug("sessionException({}) {}: {}",
                session, t.getClass().getSimpleName(), t.getMessage(), t);
        sessionClosed(session);
    }

    @SuppressWarnings("SuspiciousMethodCalls")
    @Override
    public void sessionClosed(Session s) {
        if (sessions.remove(s)) {
            if (log.isDebugEnabled()) {
                log.debug("sessionClosed({}) un-tracked", s);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("sessionClosed({}) not tracked", s);
            }
        }
    }

    @Override
    public void run() {
        for (SessionHelper session : sessions) {
            try {
                session.checkForTimeouts();
            } catch (Exception e) {
                warn("run({}) {} while checking timeouts: {}", session, e.getClass().getSimpleName(), e.getMessage(),
                        e);
            }
        }
    }
}
