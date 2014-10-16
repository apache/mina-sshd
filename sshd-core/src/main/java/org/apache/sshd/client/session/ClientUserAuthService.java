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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.util.List;

import org.apache.sshd.client.auth.deprecated.UserAuth;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;

/**
 * Client side <code>ssh-auth</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientUserAuthService extends CloseableUtils.AbstractInnerCloseable implements Service {

    public static class Factory implements ServiceFactory {

        public String getName() {
            return "ssh-userauth";
        }

        public Service create(Session session) throws IOException {
            return new ClientUserAuthService(session);
        }
    }

    protected final ClientSessionImpl session;
    protected ClientUserAuthServiceNew delegateNew;
    protected ClientUserAuthServiceOld delegateOld;
    protected boolean started;
    protected DefaultCloseFuture future = new DefaultCloseFuture(null);

    public ClientUserAuthService(Session s) {
        if (!(s instanceof ClientSessionImpl)) {
            throw new IllegalStateException("Client side service used on server side");
        }
        session = (ClientSessionImpl) s;
    }

    public ClientSessionImpl getSession() {
        return session;
    }

    public void start() {
        if (delegateNew != null) {
            delegateNew.start();
        } else if (delegateOld != null) {
            delegateOld.start();
        }
        started = true;
    }

    public void process(byte cmd, Buffer buffer) throws Exception {
        if (delegateNew != null) {
            delegateNew.process(cmd, buffer);
        } else if (delegateOld != null) {
            delegateOld.process(cmd, buffer);
        } else {
            throw new IllegalStateException();
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        if (delegateNew != null) {
            return delegateNew;
        } else if (delegateOld != null) {
            return delegateOld;
        } else {
            return builder().build();
        }
    }

    public AuthFuture auth(UserAuth userAuth) throws IOException {
        if (delegateNew != null) {
            throw new IllegalStateException();
        }
        if (delegateOld == null) {
            delegateOld = new ClientUserAuthServiceOld(session);
            if (started) {
                delegateOld.start();
            }
        }
        return delegateOld.auth(userAuth);
    }

    public AuthFuture auth(List<Object> identities, String service) throws IOException {
        if (delegateOld != null || delegateNew != null) {
            throw new IllegalStateException();
        }
        delegateNew = new ClientUserAuthServiceNew(session);
        if (started) {
            delegateNew.start();
        }
        return delegateNew.auth(identities, service);
    }

}
