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
import java.io.InputStream;
import java.nio.channels.Channel;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@code /dev/null} input stream
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NullInputStream extends InputStream implements Channel {
    private final AtomicBoolean open = new AtomicBoolean(true);

    public NullInputStream() {
        super();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public int read() throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for reading one value");
        }
        return -1;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for reading " + len + " bytes");
        }
        return -1;
    }

    @Override
    public long skip(long n) throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for skipping " + n + " bytes");
        }
        return 0L;
    }

    @Override
    public int available() throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for availability query");
        }
        return 0;
    }

    @Override
    public synchronized void reset() throws IOException {
        if (!isOpen()) {
            throw new EOFException("Stream is closed for reset");
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
