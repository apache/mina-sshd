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
package org.apache.sshd.server.session;

import java.util.ArrayList;
import java.util.List;

import org.apache.mina.core.session.IoSession;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.AbstractSessionIoHandler;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.session.AbstractSession;

/**
 * A factory of server sessions.
 * This class can be used as a way to customize the creation of server sessions.
 *
 * @see SshServer#setSessionFactory(SessionFactory) 
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SessionFactory extends AbstractSessionIoHandler {

    protected SshServer server;
    protected final List<SessionListener> listeners = new ArrayList<SessionListener>();

    public void setServer(SshServer server) {
        this.server = server;
    }

    protected AbstractSession createSession(IoSession ioSession) throws Exception {
        ServerSession session = new ServerSession(server, ioSession);
        List<SessionListener> sl = new ArrayList<SessionListener>(this.listeners);

        for (SessionListener l : sl) {
            l.sessionCreated(session);
            session.addListener(l);
        }

        return session;
    }

    /**
     * Add a session |listener|.
     *
     * @param listener the session listener to add
     */
    public void addListener(SessionListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException();
        }

        synchronized (this.listeners) {
            this.listeners.add(listener);
        }
    }

    /**
     * Remove a session |listener|.
     *
     * @param listener the session listener to remove
     */
    public void removeListener(SessionListener listener) {
        synchronized (this.listeners) {
            this.listeners.remove(listener);
        }
    }

}
