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

import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * Provides some default implementations for managing channel/connection open/close state
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractCloseable extends IoBaseCloseable {

    public enum State {
        /** Connection is open */
        Opened,
        /** Connection is being closed gracefully */
        Graceful,
        /** Connection is being terminated immediately */
        Immediate,
        /** Connection is closed */
        Closed,
        /* end */;
    }

    /**
     * Lock object for {@code Future}-s based on this closeable instance
     */
    protected final Object futureLock = new Object();

    /**
     * State of this object
     */
    protected final AtomicReference<AbstractCloseable.State> state = new AtomicReference<>(State.Opened);

    /**
     * A future that will be set 'closed' when the object is actually closed
     */
    protected final CloseFuture closeFuture;

    protected AbstractCloseable() {
        this("");
    }

    protected AbstractCloseable(String discriminator) {
        super(discriminator);
        closeFuture = new DefaultCloseFuture(discriminator, futureLock);
    }

    public Object getFutureLock() {
        return futureLock;
    }

    @Override
    public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        closeFuture.addListener(listener);
    }

    @Override
    public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        closeFuture.removeListener(listener);
    }

    @Override
    public final CloseFuture close(boolean immediately) {
        boolean debugEnabled = log.isDebugEnabled();
        if (immediately) {
            if (state.compareAndSet(State.Opened, State.Immediate)
                    || state.compareAndSet(State.Graceful, State.Immediate)) {
                if (debugEnabled) {
                    log.debug("close({}) Closing immediately", this);
                }
                preClose();
                doCloseImmediately();
                if (debugEnabled) {
                    log.debug("close({})[Immediately] closed", this);
                }
            } else {
                if (debugEnabled) {
                    log.debug("close({})[Immediately] state already {}", this, state);
                }
            }
        } else {
            if (state.compareAndSet(State.Opened, State.Graceful)) {
                if (debugEnabled) {
                    log.debug("close({}) Closing gracefully", this);
                }
                preClose();
                SshFuture<CloseFuture> grace = doCloseGracefully();
                if (grace != null) {
                    grace.addListener(future -> {
                        if (state.compareAndSet(State.Graceful, State.Immediate)) {
                            doCloseImmediately();
                            if (debugEnabled) {
                                log.debug("close({}][Graceful] - operationComplete() closed", AbstractCloseable.this);
                            }
                        }
                    });
                } else {
                    if (state.compareAndSet(State.Graceful, State.Immediate)) {
                        doCloseImmediately();
                        if (debugEnabled) {
                            log.debug("close({})[Graceful] closed", this);
                        }
                    }
                }
            } else {
                if (debugEnabled) {
                    log.debug("close({})[Graceful] state already {}", this, state);
                }
            }
        }
        return closeFuture;
    }

    @Override
    public final boolean isClosed() {
        return state.get() == State.Closed;
    }

    @Override
    public final boolean isClosing() {
        return state.get() != State.Opened;
    }

    /**
     * preClose is guaranteed to be called before doCloseGracefully or doCloseImmediately. When preClose() is called,
     * isClosing() == true
     */
    protected void preClose() {
        // nothing
    }

    protected CloseFuture doCloseGracefully() {
        return null;
    }

    /**
     * <P>
     * doCloseImmediately is called once and only once with state == Immediate
     * </P>
     *
     * <P>
     * Overriding methods should always call the base implementation. It may be called concurrently while preClose() or
     * doCloseGracefully is executing
     * </P>
     */
    protected void doCloseImmediately() {
        closeFuture.setClosed();
        state.set(State.Closed);
    }

    protected Builder builder() {
        return new Builder(futureLock);
    }
}
