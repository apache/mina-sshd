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

import java.io.IOException;
import java.nio.channels.Channel;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@code /dev/null} stream that can be closed - in which case it will throw {@link IOException}s if invoked after
 * being closed
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CloseableEmptyInputStream extends EmptyInputStream implements Channel {
    private final AtomicBoolean open = new AtomicBoolean(true);

    public CloseableEmptyInputStream() {
        super();
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public int available() throws IOException {
        if (isOpen()) {
            return super.available();
        } else {
            throw new IOException("available() stream is closed");
        }
    }

    @Override
    public int read() throws IOException {
        if (isOpen()) {
            return super.read();
        } else {
            throw new IOException("read() stream is closed");
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (isOpen()) {
            return super.read(b, off, len);
        } else {
            throw new IOException("read([])[" + off + "," + len + "] stream is closed");
        }
    }

    @Override
    public long skip(long n) throws IOException {
        if (isOpen()) {
            return super.skip(n);
        } else {
            throw new IOException("skip(" + n + ") stream is closed");
        }
    }

    @Override
    public synchronized void reset() throws IOException {
        if (isOpen()) {
            super.reset();
        } else {
            throw new IOException("reset() stream is closed");
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
