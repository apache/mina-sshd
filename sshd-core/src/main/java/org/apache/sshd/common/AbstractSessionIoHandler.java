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
package org.apache.sshd.common;

import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Readable;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSessionIoHandler implements IoHandler {

    protected abstract AbstractSession createSession(IoSession ioSession) throws Exception;

    public void sessionCreated(IoSession ioSession) throws Exception {
        AbstractSession session = createSession(ioSession);
        AbstractSession.attachSession(ioSession, session);
    }

    public void sessionClosed(IoSession ioSession) throws Exception {
        AbstractSession.getSession(ioSession).close(true);
    }

    public void exceptionCaught(IoSession ioSession, Throwable cause) throws Exception {
        AbstractSession session = AbstractSession.getSession(ioSession, true);
        if (session != null) {
            session.exceptionCaught(cause);
        } else {
            throw new IllegalStateException("No session available", cause);
        }
    }

    public void messageReceived(IoSession ioSession, Readable message) throws Exception {
        AbstractSession.getSession(ioSession).messageReceived(message);
    }

}
