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

package org.apache.sshd.contrib.common.compression;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.contrib.common.util.io.ExposedBufferByteArrayOutputStream;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DeflatingInputStream extends InputStream {
    private ExposedBufferByteArrayOutputStream baos;
    private int readPos;
    private InputStream inputStream;
    private OutputStream compressor;
    private final byte[] readBuf = new byte[IoUtils.DEFAULT_COPY_SIZE]; // TODO make it configurable
    private final byte[] oneByte = new byte[1];

    public DeflatingInputStream(InputStream inputStream, ExposedBufferByteArrayOutputStream baos, OutputStream compressor) {
        this.inputStream = Objects.requireNonNull(inputStream, "No initial input stream");
        this.baos = Objects.requireNonNull(baos, "No buffering output stream");
        this.compressor = Objects.requireNonNull(compressor, "No compressor stream");
    }

    @Override
    public int read() throws IOException {
        int readLen = read(oneByte);
        if (readLen < 0) {
            return -1;
        }

        return oneByte[0] & 0xFF;
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }

        int curOffset = off;
        int maxOffset = off + len;
        int remainLen = len;
        while ((remainLen > 0) && (curOffset < maxOffset)) {
            // see if we can use what we already compressed
            int count = baos.size();
            int available = count - readPos;
            int copyLen = Math.min(available, remainLen);
            if (copyLen > 0) {
                byte[] compressedData = baos.getBuffer();
                System.arraycopy(compressedData, readPos, buf, curOffset, copyLen);
                readPos += copyLen;
                curOffset += copyLen;
                remainLen -= copyLen;
            } else {
                int readLen = fillCompressedBuffer();
                if (readLen < 0) {
                    // if no more data available and we did not fill the buffer yet report EOF
                    if (curOffset <= off) {
                        return -1;
                    }

                    break; // report whatever we compressed so far
                }
            }
        }

        return curOffset - off;
    }

    @Override
    public long skip(long n) throws IOException {
        throw new StreamCorruptedException("Not possible to skip compressed stream " + n + " bytes");
    }

    @Override
    public int available() throws IOException {
        // keep trying until we have some data in the compression buffer or no more data available
        while (true) {
            int count = baos.size();
            int available = count - readPos;
            if (available > 0) {
                return available;
            }

            int readLen = fillCompressedBuffer();
            if (readLen < 0) {
                return 0;
            }
        }
    }

    protected int fillCompressedBuffer() throws IOException {
        int readLen = inputStream.read(readBuf);
        baos.reset();
        readPos = 0;

        // no more input so done compressing - flush it so it is reflected in the buffer array
        if (readLen < 0) {
            compressor.flush();
            compressor.close();

            // check if anything flushed
            int count = baos.size();
            if (count > 0) {
                return count;
            }

            return -1;
        }

        // start compressing some more data
        compressor.write(readBuf, 0, readLen);
        return readLen;
    }

    @Override
    public synchronized void mark(int readlimit) {
        throw new UnsupportedOperationException("mark(" + readlimit + ") N/A");
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new StreamCorruptedException("Not possible to reset compressed stream");
    }

    @Override
    public void close() throws IOException {
        IOException err = null;
        try {
            compressor.close();
        } catch (IOException e) {
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            baos.close();
        } catch (IOException e) {
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            super.close();
        } catch (IOException e) {
            err = GenericUtils.accumulateException(err, e);
        }

        if (err != null) {
            throw err;
        }
    }

}
