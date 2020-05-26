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
package org.apache.sshd.common.io.nio2;

import java.nio.ByteBuffer;
import java.util.Objects;

import org.apache.sshd.common.io.AbstractIoWriteFuture;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2DefaultIoWriteFuture extends AbstractIoWriteFuture {
    private final ByteBuffer buffer;

    public Nio2DefaultIoWriteFuture(Object id, Object lock, ByteBuffer buffer) {
        super(id, lock);
        this.buffer = buffer;
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    public void setWritten() {
        setValue(Boolean.TRUE);
    }

    public void setException(Throwable exception) {
        setValue(Objects.requireNonNull(exception, "No exception specified"));
    }
}
