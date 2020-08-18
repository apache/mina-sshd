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

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSessionIoHandler extends AbstractLoggingBean implements IoHandler {
    protected AbstractSessionIoHandler() {
        super();
    }

    @Override
    public void sessionCreated(IoSession ioSession) throws Exception {
        ValidateUtils.checkNotNull(createSession(ioSession), "No session created for %s", ioSession);
    }

    @Override
    public void sessionClosed(IoSession ioSession) throws Exception {
        AbstractSession session = AbstractSession.getSession(ioSession);
        session.close(true);
    }

    @Override
    public void exceptionCaught(IoSession ioSession, Throwable cause) throws Exception {
        AbstractSession session = AbstractSession.getSession(ioSession, true);
        if (session != null) {
            session.exceptionCaught(cause);
        } else {
            throw new MissingAttachedSessionException(
                    "No session available to signal caught exception=" + cause.getClass().getSimpleName(), cause);
        }
    }

    @Override
    public void messageReceived(IoSession ioSession, Readable message) throws Exception {
        AbstractSession session = AbstractSession.getSession(ioSession);
        try {
            session.messageReceived(message);
        } catch (Error e) {
            log.debug("messageReceived({}) failed {} to handle message: {}",
                    ioSession, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    protected abstract AbstractSession createSession(IoSession ioSession) throws Exception;
}
