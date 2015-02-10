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
package org.apache.sshd.common.session;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.sshd.common.AbstractSessionIoHandler;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.io.IoSession;

/**
 * An abstract base factory of sessions.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSessionFactory extends AbstractSessionIoHandler {

    protected final List<SessionListener> listeners = new CopyOnWriteArrayList<SessionListener>();

    protected AbstractSessionFactory() {
    	super();
    }

    protected AbstractSession createSession(IoSession ioSession) throws Exception {
        AbstractSession session = doCreateSession(ioSession);

        for (SessionListener l : listeners) {
            l.sessionCreated(session);
            session.addListener(l);
        }

        return session;
    }

    protected abstract AbstractSession doCreateSession(IoSession ioSession) throws Exception;

    /**
     * Add a session |listener|.
     *
     * @param listener the session listener to add
     */
    public void addListener(SessionListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException();
        }
        this.listeners.add(listener);
    }

    /**
     * Remove a session |listener|.
     *
     * @param listener the session listener to remove
     */
    public void removeListener(SessionListener listener) {
        this.listeners.remove(listener);
    }

}
