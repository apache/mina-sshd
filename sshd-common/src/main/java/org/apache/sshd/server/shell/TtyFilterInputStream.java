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
package org.apache.sshd.server.shell;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Handles the input while taking into account the {@link PtyMode}s for handling CR / LF
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TtyFilterInputStream extends FilterInputStream {
    public static final Set<PtyMode> INPUT_OPTIONS
            = Collections.unmodifiableSet(EnumSet.of(PtyMode.ONLCR, PtyMode.OCRNL, PtyMode.ONLRET, PtyMode.ONOCR));

    private final Set<PtyMode> ttyOptions;
    private Buffer buffer = new ByteArrayBuffer(Integer.SIZE, false);
    private int lastChar = -1;

    public TtyFilterInputStream(InputStream in, Map<PtyMode, ?> modes) {
        this(in, PtyMode.resolveEnabledOptions(modes, INPUT_OPTIONS));
    }

    public TtyFilterInputStream(InputStream in, Collection<PtyMode> ttyOptions) {
        super(Objects.requireNonNull(in, "No input stream provided"));
        // we create a copy of the options so as to avoid concurrent modifications
        this.ttyOptions = GenericUtils.of(ttyOptions); // TODO validate non-conflicting options
    }

    public synchronized void write(int c) {
        buffer.putByte((byte) c);
    }

    public synchronized void write(byte[] buf, int off, int len) {
        if (len == 1) {
            write(buf[off] & 0xFF);
        } else {
            buffer.putBytes(buf, off, len);
        }
    }

    @Override
    public synchronized int available() throws IOException {
        return super.available() + buffer.available();
    }

    @Override
    public synchronized int read() throws IOException {
        int c = readRawInput();
        if (c == -1) {
            return c;
        }

        if (c == '\r') {
            c = handleCR();
        } else if (c == '\n') {
            c = handleLF();
        }

        lastChar = c;
        return c;
    }

    protected int handleCR() throws IOException {
        if (ttyOptions.contains(PtyMode.OCRNL)) {
            return '\n'; // Translate carriage return to newline
        } else {
            return '\r';
        }
    }

    protected int handleLF() throws IOException {
        // Map NL to CR-NL.
        if ((ttyOptions.contains(PtyMode.ONLCR) || ttyOptions.contains(PtyMode.ONOCR)) && (lastChar != '\r')) {
            buffer = insertCharacter(buffer, '\n');
            return '\r';
        } else if (ttyOptions.contains(PtyMode.ONLRET)) { // Newline performs a carriage return
            return '\r';
        } else {
            return '\n';
        }
    }

    // TODO add 'insertXXX' methods to the Buffer class
    protected Buffer insertCharacter(Buffer org, int c) {
        int remaining = org.capacity();
        int readPos = org.rpos();
        // see if can accommodate the character in the original buffer
        if ((remaining > 0) && (readPos > 0)) {
            int writePos = org.wpos();
            org.wpos(readPos - 1);
            org.putByte((byte) c);
            org.wpos(writePos);
            org.rpos(readPos - 1);
            return org;
        } else {
            Buffer buf = new ByteArrayBuffer(org.available() + Byte.SIZE, false);
            buf.putByte((byte) c);
            buf.putBuffer(org);
            return buf;
        }
    }

    protected int readRawInput() throws IOException {
        if (buffer.available() > 0) {
            return buffer.getUByte();
        } else {
            return this.in.read();
        }
    }

    @Override
    public synchronized int read(byte[] b, int off, int len) throws IOException {
        if (len == 1) {
            int c = read();
            if (c == -1) {
                return -1;
            }

            b[off] = (byte) c;
            return 1;
        }

        if (buffer.available() == 0) {
            buffer.compact();
            int nb = this.in.read(b, off, len);
            if (nb == -1) {
                return nb;
            }
            buffer.putRawBytes(b, off, nb);
        }

        int nb = 0;
        for (int curPos = off; (nb < len) && (buffer.available() > 0); nb++, curPos++) {
            b[curPos] = (byte) read();
        }

        return nb;
    }
}
