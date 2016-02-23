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
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Task that iterates over all currently open {@link AbstractSession}s and checks each of them for timeouts. If
 * the {@link AbstractSession} has timed out (either auth or idle timeout), the session will be disconnected.
 *
 * @see org.apache.sshd.common.session.helpers.AbstractSession#checkForTimeouts()
 */
public class SessionTimeoutListener extends AbstractLoggingBean implements SessionListener, Runnable {
    private final Set<AbstractSession> sessions = new CopyOnWriteArraySet<AbstractSession>();

    public SessionTimeoutListener() {
        super();
    }

    @Override
    public void sessionCreated(Session session) {
        if ((session instanceof AbstractSession) && ((session.getAuthTimeout() > 0L) || (session.getIdleTimeout() > 0L))) {
            sessions.add((AbstractSession) session);
            log.debug("sessionCreated({}) tracking", session);
        } else {
            log.trace("sessionCreated({}) not tracked", session);
        }
    }

    @Override
    public void sessionEvent(Session session, Event event) {
        // ignored
    }

    @Override
    public void sessionException(Session session, Throwable t) {
        if (log.isDebugEnabled()) {
            log.debug("sessionException({}) {}: {}", session, t.getClass().getSimpleName(), t.getMessage());
        }
        if (log.isTraceEnabled()) {
            log.trace("sessionException(" + session + ") details", t);
        }
        sessionClosed(session);
    }

    @Override
    public void sessionClosed(Session s) {
        if (sessions.remove(s)) {
            log.debug("sessionClosed({}) un-tracked", s);
        } else {
            log.trace("sessionClosed({}) not tracked", s);
        }
    }

    @Override
    public void run() {
        for (AbstractSession session : sessions) {
            try {
                session.checkForTimeouts();
            } catch (Exception e) {
                log.warn(e.getClass().getSimpleName() + " while checking session=" + session + " timeouts: " + e.getMessage(), e);
            }
        }
    }
}
