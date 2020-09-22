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
package org.apache.sshd.common.channel;

import java.io.EOFException;
import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;

/**
 * An {@link IoOutputStream} capable of queuing write requests.
 */
public class BufferedIoOutputStream extends AbstractInnerCloseable implements IoOutputStream {
    protected final IoOutputStream out;
    protected final Queue<IoWriteFutureImpl> writes = new ConcurrentLinkedQueue<>();
    protected final AtomicReference<IoWriteFutureImpl> currentWrite = new AtomicReference<>();
    protected final Object id;

    public BufferedIoOutputStream(Object id, IoOutputStream out) {
        this.out = out;
        this.id = id;
    }

    public Object getId() {
        return id;
    }

    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
        if (isClosing()) {
            throw new EOFException("Closed - state=" + state);
        }

        IoWriteFutureImpl future = new IoWriteFutureImpl(getId(), buffer);
        writes.add(future);
        startWriting();
        return future;
    }

    protected void startWriting() throws IOException {
        IoWriteFutureImpl future = writes.peek();
        if (future == null) {
            return;
        }

        if (!currentWrite.compareAndSet(null, future)) {
            return;
        }

        out.writeBuffer(future.getBuffer()).addListener(
                new SshFutureListener<IoWriteFuture>() {
                    @Override
                    public void operationComplete(IoWriteFuture f) {
                        if (f.isWritten()) {
                            future.setValue(Boolean.TRUE);
                        } else {
                            future.setValue(f.getException());
                        }
                        finishWrite(future);
                    }
                });
    }

    protected void finishWrite(IoWriteFutureImpl future) {
        writes.remove(future);
        currentWrite.compareAndSet(future, null);
        try {
            startWriting();
        } catch (IOException e) {
            error("finishWrite({}) failed ({}) re-start writing: {}",
                    out, e.getClass().getSimpleName(), e.getMessage(), e);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .when(getId(), writes)
                .close(out)
                .build();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + out + "]";
    }
}
