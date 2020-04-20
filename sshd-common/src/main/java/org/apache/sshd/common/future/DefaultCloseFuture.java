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

/**
 * A default implementation of {@link CloseFuture}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultCloseFuture extends DefaultSshFuture<CloseFuture> implements CloseFuture {

    /**
     * Create a new instance
     *
     * @param id   Some identifier useful as {@code toString()} value
     * @param lock A synchronization object for locking access - if {@code null} then synchronization occurs on
     *             {@code this} instance
     */
    public DefaultCloseFuture(Object id, Object lock) {
        super(id, lock);
    }

    @Override
    public boolean isClosed() {
        if (isDone()) {
            return (Boolean) getValue();
        } else {
            return false;
        }
    }

    @Override
    public void setClosed() {
        setValue(Boolean.TRUE);
    }
}
