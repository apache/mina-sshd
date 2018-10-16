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
package org.apache.sshd.common.util;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Readable {

    int available();

    void getRawBytes(byte[] data, int offset, int len);

    /**
     * Wrap a {@link ByteBuffer} as a {@link Readable} instance
     *
     * @param buffer The {@link ByteBuffer} to wrap - never {@code null}
     * @return The {@link Readable} wrapper
     */
    static Readable readable(ByteBuffer buffer) {
        Objects.requireNonNull(buffer, "No buffer to wrap");
        return new Readable() {
            @Override
            public int available() {
                return buffer.remaining();
            }

            @Override
            public void getRawBytes(byte[] data, int offset, int len) {
                buffer.get(data, offset, len);
            }
        };
    }
}
