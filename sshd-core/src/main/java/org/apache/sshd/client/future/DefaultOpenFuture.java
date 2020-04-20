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
import java.util.Objects;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.DefaultVerifiableSshFuture;

/**
 * A default implementation of {@link OpenFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultOpenFuture extends DefaultVerifiableSshFuture<OpenFuture> implements OpenFuture {
    public DefaultOpenFuture(Object id, Object lock) {
        super(id, lock);
    }

    @Override
    public OpenFuture verify(long timeoutMillis) throws IOException {
        Boolean result = verifyResult(Boolean.class, timeoutMillis);
        if (!result) {
            throw formatExceptionMessage(
                    SshException::new,
                    "Channel opening failed while waiting %d msec.",
                    timeoutMillis);
        }

        return this;
    }

    @Override
    public Throwable getException() {
        Object v = getValue();
        if (v instanceof Throwable) {
            return (Throwable) v;
        } else {
            return null;
        }
    }

    @Override
    public boolean isOpened() {
        Object value = getValue();
        return (value instanceof Boolean) && (Boolean) value;
    }

    @Override
    public void setOpened() {
        setValue(Boolean.TRUE);
    }

    @Override
    public void setException(Throwable exception) {
        Objects.requireNonNull(exception, "No exception provided");
        setValue(exception);
    }
}
