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
package org.apache.sshd.common.future;

import java.util.Objects;
import java.util.concurrent.CancellationException;

/**
 * A default {@link Cancellable} future implementation.
 *
 * @param  <T> Type of future
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class DefaultCancellableSshFuture<T extends SshFuture<T>>
        extends DefaultVerifiableSshFuture<T>
        implements Cancellable {

    protected DefaultCancellableSshFuture(Object id, Object lock) {
        super(id, lock);
    }

    @Override
    public boolean isCanceled() {
        return getValue() instanceof CancelFuture;
    }

    @Override
    protected CancelFuture createCancellation() {
        return new DefaultCancelFuture(getId());
    }

    @Override
    public CancelFuture cancel() {
        CancelFuture cancellation = createCancellation();
        if (cancellation == null) {
            return getCancellation();
        }
        cancellation.setBackTrace(new CancellationException("Programmatically canceled"));
        setValue(cancellation);
        return getCancellation();
    }

    @Override
    public CancelFuture getCancellation() {
        Object v = getValue();
        return (v instanceof CancelFuture) ? (CancelFuture) v : null;
    }

    @Override
    public Throwable getException() {
        Object v = getValue();
        return (v instanceof Throwable) ? (Throwable) v : null;
    }

    /**
     * {@inheritDoc}
     *
     * If the {@code exception} cannot be set but the future is already canceled, the exception will be reported through
     * this future's {@link CancelFuture}.
     */
    @Override
    public void setException(Throwable exception) {
        setValue(Objects.requireNonNull(exception, "No exception provided"));
        if (getException() == null) {
            CancelFuture cancellation = getCancellation();
            if (cancellation != null) {
                cancellation.setCanceled(exception);
            }
        }
    }

}
