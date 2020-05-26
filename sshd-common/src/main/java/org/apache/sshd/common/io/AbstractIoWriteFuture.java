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

package org.apache.sshd.common.io;

import java.io.IOException;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.DefaultVerifiableSshFuture;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIoWriteFuture
        extends DefaultVerifiableSshFuture<IoWriteFuture>
        implements IoWriteFuture {
    protected AbstractIoWriteFuture(Object id, Object lock) {
        super(id, lock);
    }

    @Override
    public IoWriteFuture verify(long timeout) throws IOException {
        Boolean result = verifyResult(Boolean.class, timeout);
        if (!result) {
            throw formatExceptionMessage(
                    SshException::new,
                    "Write failed signalled while wait %d msec.",
                    timeout);
        }

        return this;
    }

    @Override
    public boolean isWritten() {
        Object value = getValue();
        return (value instanceof Boolean) && (Boolean) value;
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
}
