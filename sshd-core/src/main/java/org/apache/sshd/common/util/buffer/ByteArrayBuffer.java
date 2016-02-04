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

package org.apache.sshd.common.util.buffer;

import java.nio.charset.Charset;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Provides an implementation of {@link Buffer} using a backing byte array
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ByteArrayBuffer extends Buffer {
    public static final int DEFAULT_SIZE = 256;
    public static final int MAX_LEN = 65536;

    private byte[] data;
    private int rpos;
    private int wpos;

    public ByteArrayBuffer() {
        this(DEFAULT_SIZE);
    }

    public ByteArrayBuffer(int size) {
        this(size, true);
    }

    public ByteArrayBuffer(int size, boolean roundOff) {
        this(new byte[roundOff ? BufferUtils.getNextPowerOf2(size) : size], false);
    }

    public ByteArrayBuffer(byte[] data) {
        this(data, 0, data.length, true);
    }

    public ByteArrayBuffer(byte[] data, boolean read) {
        this(data, 0, data.length, read);
    }

    public ByteArrayBuffer(byte[] data, int off, int len) {
        this(data, off, len, true);
    }

    public ByteArrayBuffer(byte[] data, int off, int len, boolean read) {
        this.data = data;
        this.rpos = off;
        this.wpos = (read ? len : 0) + off;
    }

    @Override
    public int rpos() {
        return rpos;
    }

    @Override
    public void rpos(int rpos) {
        this.rpos = rpos;
    }

    @Override
    public int wpos() {
        return wpos;
    }

    @Override
    public void wpos(int wpos) {
        if (wpos > this.wpos) {
            ensureCapacity(wpos - this.wpos);
        }
        this.wpos = wpos;
    }

    @Override
    public int available() {
        return wpos - rpos;
    }

    @Override
    public int capacity() {
        return data.length - wpos;
    }

    @Override
    public byte[] array() {
        return data;
    }

    @Override
    public void compact() {
        int avail = available();
        if (avail > 0) {
            System.arraycopy(data, rpos, data, 0, avail);
        }
        wpos -= rpos;
        rpos = 0;
    }

    @Override
    public void clear() {
        rpos = 0;
        wpos = 0;
    }

    @Override
    public byte getByte() {
        // TODO use Byte.BYTES for JDK-8
        ensureAvailable(Byte.SIZE / Byte.SIZE);
        return data[rpos++];
    }

    @Override
    public void putByte(byte b) {
        // TODO use Byte.BYTES in JDK-8
        ensureCapacity(Byte.SIZE / Byte.SIZE);
        data[wpos++] = b;
    }

    @Override
    public int putBuffer(Readable buffer, boolean expand) {
        int r = expand ? buffer.available() : Math.min(buffer.available(), capacity());
        ensureCapacity(r);
        buffer.getRawBytes(data, wpos, r);
        wpos += r;
        return r;
    }

    @Override
    public void putRawBytes(byte[] d, int off, int len) {
        ValidateUtils.checkTrue(len >= 0, "Negative raw bytes length: %d", len);
        ensureCapacity(len);
        System.arraycopy(d, off, data, wpos, len);
        wpos += len;
    }

    @Override
    public String getString(Charset charset) {
        int len = getInt();
        if (len < 0) {
            throw new BufferException("Bad item length: " + len);
        }
        ensureAvailable(len);
        String s = new String(data, rpos, len, charset);
        rpos += len;
        return s;
    }

    @Override
    public void getRawBytes(byte[] buf, int off, int len) {
        ensureAvailable(len);
        System.arraycopy(data, rpos, buf, off, len);
        rpos += len;
    }

    @Override
    public void ensureCapacity(int capacity, Int2IntFunction growthFactor) {
        ValidateUtils.checkTrue(capacity >= 0, "Negative capacity requested: %d", capacity);

        int maxSize = size();
        int curPos = wpos();
        int remaining = maxSize - curPos;
        if (remaining < capacity) {
            int minimum = curPos + capacity;
            int actual = growthFactor.apply(minimum);
            if (actual < minimum) {
                throw new IllegalStateException("ensureCapacity(" + capacity + ") actual (" + actual + ") below min. (" + minimum + ")");
            }
            byte[] tmp = new byte[actual];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }

    @Override
    protected int size() {
        return data.length;
    }

    /**
     * Creates a compact buffer (i.e., one that starts at offset zero) containing a <U>copy</U>
     * of the original data
     *
     * @param data   The original data buffer
     * @return A {@link ByteArrayBuffer} containing a <U>copy</U> of the original data
     * starting at zero read position
     * @see #getCompactClone(byte[], int, int)
     */
    public static ByteArrayBuffer getCompactClone(byte[] data) {
        return getCompactClone(data, 0, NumberUtils.length(data));
    }

    /**
     * Creates a compact buffer (i.e., one that starts at offset zero) containing a <U>copy</U>
     * of the original data
     *
     * @param data   The original data buffer
     * @param offset The offset of the valid data in the buffer
     * @param len    The size (in bytes) of of the valid data in the buffer
     * @return A {@link ByteArrayBuffer} containing a <U>copy</U> of the original data
     * starting at zero read position
     */
    public static ByteArrayBuffer getCompactClone(byte[] data, int offset, int len) {
        byte[] clone = (len > 0) ? new byte[len] : GenericUtils.EMPTY_BYTE_ARRAY;
        if (len > 0) {
            System.arraycopy(data, offset, clone, 0, len);
        }

        return new ByteArrayBuffer(clone, true);
    }
}
