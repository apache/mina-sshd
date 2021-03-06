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

package org.apache.sshd.contrib.common.util.io;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Calls the actual writing method only when LF detected in the written stream. <B>Note:</B> it strips CR if found
 * before the LF
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class LineOutputStream extends OutputStream {
    protected final byte[] oneByte = new byte[1];
    protected byte[] lineBuf;
    protected int usedLen;

    protected LineOutputStream() {
        super();
    }

    @Override
    public void write(int b) throws IOException {
        oneByte[0] = (byte) (b & 0xff);
        write(oneByte, 0, 1);
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        int lastOffset = off;
        int maxOffset = off + len;
        for (int curOffset = off; curOffset < maxOffset; curOffset++) {
            byte ch = b[curOffset];
            if (ch != 0x0a) {
                continue;
            }

            // Any previous line segment ?
            if (usedLen > 0) {
                accumulateLineData(b, lastOffset, curOffset - lastOffset);

                // Strip CR
                if (lineBuf[usedLen - 1] == 0x0d) {
                    usedLen--;
                }
                handleLine(lineBuf, 0, usedLen);
                usedLen = 0;
            } else {
                int lineLen = curOffset - lastOffset;
                // Strip CR
                if ((lineLen > 0) && (b[curOffset - 1] == 0x0d)) {
                    lineLen--;
                }
                handleLine(b, lastOffset, lineLen);
            }

            lastOffset = curOffset + 1;
        }

        // any leftovers ?
        if (lastOffset < maxOffset) {
            accumulateLineData(b, lastOffset, maxOffset - lastOffset);
        }
    }

    protected void accumulateLineData(byte[] b, int off, int len) throws IOException {
        if (len <= 0) {
            return;
        }

        int reqLen = usedLen + len;
        if ((lineBuf == null) || (reqLen >= lineBuf.length)) {
            byte[] tmp = new byte[reqLen + Byte.SIZE /* a bit extra to avoid frequent re-sizing */];
            if (usedLen > 0) {
                System.arraycopy(lineBuf, 0, tmp, 0, usedLen);
            }
            lineBuf = tmp;
        }

        System.arraycopy(b, off, lineBuf, usedLen, len);
        usedLen += len;
    }

    protected abstract void handleLine(byte[] buf, int offset, int len) throws IOException;

    @Override
    public void close() throws IOException {
        // Last line might not be LF terminated
        if (usedLen > 0) {
            // Strip CR
            if (lineBuf[usedLen - 1] == 0x0d) {
                usedLen--;
            }

            handleLine(lineBuf, 0, usedLen);
            usedLen = 0;
        }
    }
}
