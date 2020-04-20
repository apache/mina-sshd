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

import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Future holding a packet pending key exchange termination.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PendingWriteFuture extends AbstractIoWriteFuture implements SshFutureListener<IoWriteFuture> {
    private final Buffer buffer;

    public PendingWriteFuture(Object id, Buffer buffer) {
        super(id, null);
        this.buffer = Objects.requireNonNull(buffer, "No buffer provided");
    }

    public Buffer getBuffer() {
        return buffer;
    }

    public void setWritten() {
        setValue(Boolean.TRUE);
    }

    public void setException(Throwable cause) {
        Objects.requireNonNull(cause, "No cause specified");
        setValue(cause);
    }

    @Override
    public void operationComplete(IoWriteFuture future) {
        if (future.isWritten()) {
            setWritten();
        } else {
            setException(future.getException());
        }
    }
}
