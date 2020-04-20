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

package org.apache.sshd.common.util.io;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channel;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {code /dev/null} output stream
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NullOutputStream extends OutputStream implements Channel {
    private final AtomicBoolean open = new AtomicBoolean(true);

    public NullOutputStream() {
        super();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void write(int b) throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for writing one byte");
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for writing " + len + " bytes");
        }
    }

    @Override
    public void flush() throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for flushing");
        }
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            // noinspection UnnecessaryReturnStatement
            return; // debug breakpoint
        }
    }
}
