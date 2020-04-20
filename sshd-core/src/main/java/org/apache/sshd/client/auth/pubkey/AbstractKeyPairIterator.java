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

package org.apache.sshd.client.auth.pubkey;

import java.util.Iterator;
import java.util.Objects;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;

/**
 * @param  <I> Type of {@link PublicKeyIdentity} being iterated
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractKeyPairIterator<I extends PublicKeyIdentity>
        implements Iterator<I>, SessionHolder<ClientSession>, ClientSessionHolder {

    private final ClientSession session;

    protected AbstractKeyPairIterator(ClientSession session) {
        this.session = Objects.requireNonNull(session, "No session");
    }

    @Override
    public final ClientSession getClientSession() {
        return session;
    }

    @Override
    public final ClientSession getSession() {
        return getClientSession();
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("No removal allowed");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getClientSession() + "]";
    }
}
