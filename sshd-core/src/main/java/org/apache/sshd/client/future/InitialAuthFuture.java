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

import org.apache.sshd.common.future.SshFutureListener;

/**
 * A special future used until the authentication service replaces it with a &quot;real&quot; one. This future serves as
 * a placeholder for any exceptions caught until authentication starts. It is special in one other way - it has no
 * listeners attached to it and expects no authentication success or failure - only exceptions.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class InitialAuthFuture extends DefaultAuthFuture {
    public InitialAuthFuture(Object id, Object lock) {
        super(id, lock);
    }

    @Override
    public AuthFuture addListener(SshFutureListener<AuthFuture> listener) {
        throw new UnsupportedOperationException("Not allowed to add listeners to this future");
    }

    @Override
    protected void notifyListener(SshFutureListener<AuthFuture> l) {
        if (l != null) {
            throw new UnsupportedOperationException("No listeners expected for this future");
        }
    }

    @Override
    public void setAuthed(boolean authed) {
        throw new UnsupportedOperationException("No authentication expected for this future");
    }
}
