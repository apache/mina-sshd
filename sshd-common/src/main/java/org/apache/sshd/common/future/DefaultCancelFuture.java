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

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/**
 * A default implementation of a {@link CancelFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultCancelFuture extends DefaultSshFuture<CancelFuture> implements CancelFuture {

    private CancellationException backTrace;

    protected DefaultCancelFuture(Object id) {
        super(id, null);
    }

    /**
     * {@inheritDoc}
     *
     * @return the value of {@link #isCanceled()}
     */
    @Override
    public Boolean verify(long timeoutMillis, CancelOption... options) throws IOException {
        return verifyResult(Boolean.class, timeoutMillis, options);
    }

    @Override
    public void setCanceled() {
        setCanceled(null);
    }

    @Override
    public void setCanceled(Throwable error) {
        synchronized (this) {
            // Normally we create a backtrace right when we create the CancelFuture. If the future doesn't have a
            // backtrace yet, at least record where the future was fulfilled.
            if (backTrace == null) {
                backTrace = new CancellationException("Canceled by framework");
            }
            if (error != null) {
                backTrace.addSuppressed(error);
            }
        }
        setValue(Boolean.TRUE);
    }

    @Override
    public void setNotCanceled() {
        setValue(Boolean.FALSE);
    }

    @Override
    public boolean isCanceled() {
        return Boolean.TRUE.equals(getValue());
    }

    @Override
    public void setBackTrace(CancellationException backTrace) {
        synchronized (this) {
            if (this.backTrace == null) {
                this.backTrace = Objects.requireNonNull(backTrace, "Cancellation backtrace must not be null");
            }
        }
    }

    @Override
    public CancellationException getBackTrace() {
        synchronized (this) {
            return backTrace;
        }
    }
}
