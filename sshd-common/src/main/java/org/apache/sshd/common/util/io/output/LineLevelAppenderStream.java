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

package org.apache.sshd.common.util.io.output;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * <P>
 * Accumulates all written data into a work buffer and calls the actual writing method only when LF detected.
 * <B>Note:</B> it strips CR if found before the LF
 * </P>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LineLevelAppenderStream extends LineOutputStream {
    protected final CharsetDecoder csDecoder;
    protected final LineLevelAppender appenderInstance;
    protected char[] lineBuf;

    public LineLevelAppenderStream(LineLevelAppender appender) {
        this(Charset.defaultCharset(), appender);
    }

    public LineLevelAppenderStream(String charset, LineLevelAppender appender) {
        this(Charset.forName(ValidateUtils.checkNotNullAndNotEmpty(charset, "No charset name")), appender);
    }

    public LineLevelAppenderStream(Charset charset, LineLevelAppender appender) {
        this(Objects.requireNonNull(charset, "No charset").newDecoder(), appender);
    }

    public LineLevelAppenderStream(CharsetDecoder decoder, LineLevelAppender appender) {
        csDecoder = Objects.requireNonNull(decoder, "No decoder");
        appenderInstance = Objects.requireNonNull(appender, "No appender");
    }

    public final LineLevelAppender getLineLevelAppender() {
        return appenderInstance;
    }

    @Override
    protected void handleLine(byte[] b, int off, int len) throws IOException {
        LineLevelAppender appender = getLineLevelAppender();
        if (len <= 0) {
            appender.writeLineData("");
            return;
        }

        ByteBuffer bb = (b[off + len - 1] == '\r') ? ByteBuffer.wrap(b, off, len - 1) : ByteBuffer.wrap(b, off, len);
        char[] lineChars = ensureCharDataCapacity(len);
        CharBuffer cc = CharBuffer.wrap(lineChars);

        csDecoder.reset();
        CoderResult res = csDecoder.decode(bb, cc, true);
        if (res.isError() || res.isMalformed() || res.isOverflow() || res.isUnmappable()) {
            throw new StreamCorruptedException("Failed to decode line bytes: " + res);
        }

        cc.flip();
        appender.writeLineData(cc);
    }

    protected char[] ensureCharDataCapacity(int numBytes) {
        float grwFactor = csDecoder.maxCharsPerByte(); // worst case
        int reqChars = (grwFactor > 0.0f) ? (int) (numBytes * grwFactor) : numBytes;
        if ((lineBuf == null) || (lineBuf.length < reqChars)) {
            reqChars = Math.max(reqChars, LineLevelAppender.TYPICAL_LINE_LENGTH);
            lineBuf = new char[reqChars + Byte.SIZE /* a little extra to avoid numerous growths */];
        }

        return lineBuf;
    }
}
