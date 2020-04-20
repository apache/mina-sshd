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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Handles the output stream while taking care of the {@link PtyMode} for CR / LF and ECHO settings
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TtyFilterOutputStream extends FilterOutputStream {
    public static final Set<PtyMode> OUTPUT_OPTIONS
            = Collections.unmodifiableSet(EnumSet.of(PtyMode.ECHO, PtyMode.INLCR, PtyMode.ICRNL, PtyMode.IGNCR));

    private final Set<PtyMode> ttyOptions;
    private final TtyFilterInputStream echo;

    public TtyFilterOutputStream(OutputStream out, TtyFilterInputStream echo, Map<PtyMode, ?> modes) {
        this(out, echo, PtyMode.resolveEnabledOptions(modes, OUTPUT_OPTIONS));
    }

    public TtyFilterOutputStream(OutputStream out, TtyFilterInputStream echo, Collection<PtyMode> ttyOptions) {
        super(out);
        // we create a copy of the options so as to avoid concurrent modifications
        this.ttyOptions = GenericUtils.of(ttyOptions); // TODO validate non-conflicting options
        this.echo = this.ttyOptions.contains(PtyMode.ECHO) ? Objects.requireNonNull(echo, "No echo stream") : echo;
    }

    @Override
    public void write(int c) throws IOException {
        if (c == '\r') {
            handleCR();
        } else if (c == '\n') {
            handleLF();
        } else {
            writeRawOutput(c);
        }
    }

    protected void handleCR() throws IOException {
        if (ttyOptions.contains(PtyMode.ICRNL)) {
            writeRawOutput('\n'); // Map CR to NL on input
        } else if (ttyOptions.contains(PtyMode.IGNCR)) {
            // Ignore CR on input
            return;
        } else {
            writeRawOutput('\r');
        }
    }

    protected void handleLF() throws IOException {
        if (ttyOptions.contains(PtyMode.INLCR)) {
            writeRawOutput('\r'); // Map NL into CR on input
        } else {
            writeRawOutput('\n');
        }
    }

    protected void writeRawOutput(int c) throws IOException {
        this.out.write(c);
        if (ttyOptions.contains(PtyMode.ECHO)) {
            echo.write(c);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (len == 1) {
            write(b[off] & 0xFF);
            return;
        }

        int lastPos = 0;
        int maxPos = off + len;
        for (int curPos = off; curPos < maxPos; curPos++) {
            int c = b[curPos] & 0xFF;
            if ((c == '\r') || (c == '\n')) {
                if (lastPos < curPos) { // No CR or LF in this segment
                    writeRawOutput(b, lastPos, curPos - lastPos);
                }

                lastPos = curPos + 1; // prepare for next character
                write(c);
            }
        }

        if (lastPos < maxPos) { // No CR or LF in this segment
            writeRawOutput(b, lastPos, maxPos - lastPos);
        }
    }

    protected void writeRawOutput(byte[] b, int off, int len) throws IOException {
        this.out.write(b, off, len);
        if (ttyOptions.contains(PtyMode.ECHO)) {
            echo.write(b, off, len);
        }
    }
}
