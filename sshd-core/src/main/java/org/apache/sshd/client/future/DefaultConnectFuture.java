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
package org.apache.sshd.client.future;

import java.io.IOException;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.future.DefaultVerifiableSshFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A default implementation of {@link ConnectFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultConnectFuture extends DefaultVerifiableSshFuture<ConnectFuture> implements ConnectFuture {
    public DefaultConnectFuture(Object lock) {
        super(lock);
    }

    @Override   // TODO in JDK-8 make this a default method
    public ConnectFuture verify(long timeout) throws IOException {
        long startTime = System.nanoTime();
        ClientSession session = verifyResult(ClientSession.class, timeout);
        long endTime = System.nanoTime();
        if (log.isDebugEnabled()) {
            IoSession ioSession = session.getIoSession();
            log.debug("Connected to " + ioSession.getRemoteAddress() + " after " + (endTime - startTime) + " nanos");
        }
        return this;
    }

    @Override   // TODO in JDK-8 make this a default method
    public ClientSession getSession() {
        Object v = getValue();
        if (v instanceof RuntimeException) {
            throw (RuntimeException) v;
        } else if (v instanceof Error) {
            throw (Error) v;
        } else if (v instanceof Throwable) {
            throw (RuntimeSshException) new RuntimeSshException("Failed to get the session.").initCause((Throwable) v);
        } else if (v instanceof ClientSession) {
            return (ClientSession) v;
        } else {
            return null;
        }
    }

    @Override   // TODO in JDK-8 make this a default method
    public Throwable getException() {
        Object v = getValue();
        if (v instanceof Throwable) {
            return (Throwable) v;
        } else {
            return null;
        }
    }

    @Override   // TODO in JDK-8 make this a default method
    public boolean isConnected() {
        return getValue() instanceof ClientSession;
    }

    @Override   // TODO in JDK-8 make this a default method
    public void setSession(ClientSession session) {
        ValidateUtils.checkNotNull(session, "No client session provided");
        setValue(session);
    }

    @Override   // TODO in JDK-8 make this a default method
    public void setException(Throwable exception) {
        ValidateUtils.checkNotNull(exception, "No exception provided");
        setValue(exception);
    }
}
