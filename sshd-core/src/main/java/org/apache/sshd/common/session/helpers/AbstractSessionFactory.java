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

import java.util.Objects;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoSession;

/**
 * An abstract base factory of sessions.
 *
 * @param  <M> Type of {@link FactoryManager}
 * @param  <S> Type of {@link AbstractSession}
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSessionFactory<M extends FactoryManager, S extends AbstractSession>
        extends AbstractSessionIoHandler {
    private final M manager;

    protected AbstractSessionFactory(M manager) {
        this.manager = Objects.requireNonNull(manager, "No factory manager instance");
    }

    public M getFactoryManager() {
        return manager;
    }

    @Override
    protected S createSession(IoSession ioSession) throws Exception {
        S session = doCreateSession(ioSession);
        return setupSession(session);
    }

    protected abstract S doCreateSession(IoSession ioSession) throws Exception;

    protected S setupSession(S session) throws Exception {
        return session;
    }
}
