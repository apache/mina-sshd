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

package org.apache.sshd.common.session;

import java.util.Objects;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SessionWorkBuffer extends ByteArrayBuffer implements SessionHolder<Session> {
    private final Session session;

    public SessionWorkBuffer(Session session) {
        this.session = Objects.requireNonNull(session, "No session");
    }

    @Override
    public Session getSession() {
        return session;
    }

    @Override
    public Buffer clear(boolean wipeData) {
        throw new UnsupportedOperationException("Not allowed to clear session work buffer of " + getSession());
    }

    public void forceClear(boolean wipeData) {
        super.clear(wipeData);
    }
}
