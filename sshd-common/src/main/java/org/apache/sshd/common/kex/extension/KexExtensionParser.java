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

package org.apache.sshd.common.kex.extension;

import java.io.IOException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Parses a known KEX extension
 *
 * @param  <T> Extension generic type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KexExtensionParser<T> extends NamedResource {
    default T parseExtension(byte[] data) throws IOException {
        return parseExtension(data, 0, data.length);
    }

    default T parseExtension(byte[] data, int off, int len) throws IOException {
        return parseExtension(new ByteArrayBuffer(data, off, len));
    }

    T parseExtension(Buffer buffer) throws IOException;

    /**
     * Adds the name + value to the buffer
     *
     * @param  value       The value of the extension
     * @param  buffer      The target {@link Buffer}
     * @throws IOException If failed to encode
     */
    void putExtension(T value, Buffer buffer) throws IOException;
}
