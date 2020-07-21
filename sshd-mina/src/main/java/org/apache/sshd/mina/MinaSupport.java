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
package org.apache.sshd.mina;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MinaSupport {
    private MinaSupport() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static Readable asReadable(final IoBuffer buffer) {
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

    public static IoBuffer asIoBuffer(Buffer buffer) {
        return IoBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
    }
}
