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

package org.apache.sshd.cli.client.helper;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpFileTransferProgressOutputStream extends FilterOutputStream {
    public static final char DEFAULT_PROGRESS_CHAR = '#';
    public static final int DEFAULT_MARKS_PER_LINE = 72;
    public static final int DEFAULT_MARKER_SIZE = IoUtils.DEFAULT_COPY_SIZE;

    private final int markerSize;
    private final char markerChar;
    private final int markersPerLine;
    private final Appendable stdout;
    private final byte[] workBuf = { 0 };
    private long byteCount;
    private long lastMarkOffset;
    private int curMarkersInLine;

    public SftpFileTransferProgressOutputStream(OutputStream out, Appendable stdout) {
        this(out, DEFAULT_MARKER_SIZE, DEFAULT_PROGRESS_CHAR, DEFAULT_MARKS_PER_LINE, stdout);
    }

    public SftpFileTransferProgressOutputStream(
                                                OutputStream out, int markerSize, char markerChar, int markersPerLine,
                                                Appendable stdout) {
        super(Objects.requireNonNull(out, "No target stream"));

        ValidateUtils.checkTrue(markerSize > 0, "Invalid marker size: %d", markerSize);
        this.markerSize = markerSize;

        if ((markerChar <= ' ') || (markerChar > 0x7E)) {
            throw new IllegalArgumentException("Non-printable marker character: 0x" + Integer.toHexString(markerChar));
        }
        this.markerChar = markerChar;

        ValidateUtils.checkTrue(markersPerLine > 0, "Invalid markers per line: %d", markersPerLine);

        this.markersPerLine = markersPerLine;
        this.stdout = Objects.requireNonNull(stdout, "No progress report target");
    }

    public int getMarkerSize() {
        return markerSize;
    }

    public char getMarkerChar() {
        return markerChar;
    }

    public int getMarkersPerLine() {
        return markersPerLine;
    }

    public Appendable getStdout() {
        return stdout;
    }

    @Override
    public void write(int b) throws IOException {
        workBuf[0] = (byte) (b & 0xFF);
        write(workBuf, 0, 1);
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if ((len < 0) || (off < 0)) {
            throw new StreamCorruptedException("Invalid offset (" + off + ")/length(" + len + ")");
        }
        this.out.write(b, off, len);

        byteCount += len;

        long reportDiff = byteCount - lastMarkOffset;
        int reportSize = getMarkerSize();
        long markersCount = reportDiff / reportSize;
        appendMarkers((int) markersCount);
        lastMarkOffset += markersCount * reportSize;
    }

    protected void appendMarkers(int markersCount) throws IOException {
        if (markersCount <= 0) {
            return;
        }

        Appendable target = getStdout();
        char marker = getMarkerChar();
        for (int index = 1, limit = getMarkersPerLine(); index <= markersCount; index++) {
            target.append(marker);
            curMarkersInLine++;
            if (curMarkersInLine >= limit) {
                target.append(System.lineSeparator());
                curMarkersInLine = 0;
            }
        }
    }
}
