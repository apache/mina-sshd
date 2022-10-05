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

import java.io.IOException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.future.CancelOption;
import org.apache.sshd.common.future.DefaultCancellableSshFuture;

/**
 * A default implementation of {@link AuthFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultAuthFuture extends DefaultCancellableSshFuture<AuthFuture> implements AuthFuture {

    private final CancelFuture cancellation;

    private AtomicBoolean cancellable = new AtomicBoolean(true);

    public DefaultAuthFuture(Object id, Object lock) {
        super(id, lock);
        cancellation = createCancellation();
        addListener(self -> {
            if (isDone()) {
                Object value = getValue();
                if (!(value instanceof CancelFuture)) {
                    cancellation.setNotCanceled();
                }
            }
        });
    }

    @Override
    public AuthFuture verify(long timeoutMillis, CancelOption... options) throws IOException {
        Boolean result = verifyResult(Boolean.class, timeoutMillis, options);
        if (!result) {
            throw formatExceptionMessage(
                    SshException::new,
                    "Authentication failed while waiting %d msec.",
                    timeoutMillis);
        }

        return this;
    }

    @Override
    public boolean isSuccess() {
        Object v = getValue();
        return (v instanceof Boolean) && (Boolean) v;
    }

    @Override
    public boolean isFailure() {
        Object v = getValue();
        if (v instanceof Boolean) {
            return !(Boolean) v;
        } else {
            return true;
        }
    }

    @Override
    public void setAuthed(boolean authed) {
        setValue(authed);
    }

    // Authentication is not always cancellable. It's an exchange of multiple requests and replies. Per
    // RFC 4254 https://www.rfc-editor.org/rfc/rfc4252#section-5.1, "A client MUST NOT send a subsequent
    // request if it has not received a response from the server for a previous request." This implies
    // that an authentication is only cancellable if we're not potentially expecting an SSH_MSG_USERAUTH_SUCCESS,
    // and cancellation can take only effect once we have received an outstanding intermediate reply.

    /**
     * {@inheritDoc}
     *
     * Note that returned {@link CancelFuture} may also be fulfilled unsuccessfully (i.e., ({@link #isDone()}
     * {@code && !}{@link #isCanceled()}{@code ) == true}.
     *
     * @return A {@link CancelFuture} that can be used to wait until the cancellation has been effected or the
     *         {@link AuthFuture} has been fulfilled; never {@code null}.
     */
    @Override
    public CancelFuture cancel() {
        cancellation.setBackTrace(new CancellationException("Programmatically canceled"));
        if (cancellable.get()) {
            setValue(cancellation);
        }
        return cancellation;
    }

    @Override
    public CancelFuture getCancellation() {
        return wasCanceled() ? cancellation : null;
    }

    @Override
    public boolean wasCanceled() {
        return cancellation.getBackTrace() != null;
    }

    @Override
    public void setCancellable(boolean cancellable) {
        this.cancellable.set(cancellable);
        if (wasCanceled() && this.cancellable.get()) {
            setValue(cancellation);
        }
    }
}
