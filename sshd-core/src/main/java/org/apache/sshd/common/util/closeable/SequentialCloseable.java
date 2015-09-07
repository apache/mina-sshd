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
package org.apache.sshd.common.util.closeable;

import java.util.Collections;
import java.util.Iterator;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * Waits for a group of {@link Closeable}s to complete in the given order, then
 * signals the completion by setting the &quot;parent&quot; future as closed
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SequentialCloseable extends SimpleCloseable {

    private final Iterable<? extends Closeable> closeables;

    public SequentialCloseable(Object lock, Iterable<? extends Closeable> closeables) {
        super(lock);
        this.closeables = (closeables == null) ? Collections.<Closeable>emptyList() : closeables;
    }

    @Override
    protected void doClose(final boolean immediately) {
        final Iterator<? extends Closeable> iterator = closeables.iterator();
        SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void operationComplete(CloseFuture previousFuture) {
                while (iterator.hasNext()) {
                    Closeable c = iterator.next();
                    if (c != null) {
                        if (log.isTraceEnabled()) {
                            log.trace("doClose(" + immediately + ") closing " + c);
                        }
                        CloseFuture nextFuture = c.close(immediately);
                        nextFuture.addListener(this);
                        return;
                    }
                }
                if (!iterator.hasNext()) {
                    if (log.isDebugEnabled()) {
                        log.debug("doClose(" + immediately + ") signal close complete");
                    }
                    future.setClosed();
                }
            }
        };
        listener.operationComplete(null);
    }
}