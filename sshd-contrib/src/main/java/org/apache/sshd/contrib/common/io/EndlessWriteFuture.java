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

package org.apache.sshd.contrib.common.io;

import java.io.IOException;

import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;

/**
 * Never signals a successful write completion and ignores all listeners
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EndlessWriteFuture implements IoWriteFuture {
    public static final EndlessWriteFuture INSTANCE = new EndlessWriteFuture();

    public EndlessWriteFuture() {
        super();
    }

    @Override
    public IoWriteFuture verify(long timeoutMillis) throws IOException {
        await(timeoutMillis);
        return null;
    }

    @Override
    public boolean isDone() {
        return false;
    }

    @Override
    public Object getId() {
        return "ENDLESS";
    }

    @Override
    public boolean awaitUninterruptibly(long timeoutMillis) {
        try {
            Thread.sleep(timeoutMillis);
        } catch (InterruptedException e) {
            // ignored
        }

        return false;
    }

    @Override
    public boolean await(long timeoutMillis) throws IOException {
        return awaitUninterruptibly(timeoutMillis);
    }

    @Override
    public IoWriteFuture removeListener(SshFutureListener<IoWriteFuture> listener) {
        return this;
    }

    @Override
    public IoWriteFuture addListener(SshFutureListener<IoWriteFuture> listener) {
        return this;
    }

    @Override
    public boolean isWritten() {
        return false;
    }

    @Override
    public Throwable getException() {
        return null;
    }
}
