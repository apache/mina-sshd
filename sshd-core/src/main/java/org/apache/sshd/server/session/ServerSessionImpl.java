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
package org.apache.sshd.server.session;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.ServerFactoryManager;

/**
 * The default implementation for a {@link ServerSession}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerSessionImpl extends AbstractServerSession {
    public ServerSessionImpl(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(server, ioSession);

        if (log.isDebugEnabled()) {
            log.debug("Server session created {}", ioSession);
        }

        // Inform the listener of the newly created session
        SessionListener listener = getSessionListenerProxy();
        try {
            listener.sessionCreated(this);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            if (log.isDebugEnabled()) {
                log.debug("Failed ({}) to announce session={} created: {}",
                          e.getClass().getSimpleName(), ioSession, e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("Session=" + ioSession + " creation failure details", e);
            }
            if (e instanceof Exception) {
                throw (Exception) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }

        String headerConfig = PropertyResolverUtils.getString(this, ServerFactoryManager.SERVER_EXTRA_IDENTIFICATION_LINES);
        String[] headers = GenericUtils.split(headerConfig, ServerFactoryManager.SERVER_EXTRA_IDENT_LINES_SEPARATOR);
        sendServerIdentification(headers);
    }
}
