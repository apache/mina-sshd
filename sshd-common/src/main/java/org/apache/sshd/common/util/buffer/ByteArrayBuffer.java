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

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Provides an implementation of {@link Buffer} using a backing byte array
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ByteArrayBuffer extends Buffer {
    /**
     * Initial default allocated buffer size if none specified
     */
    public static final int DEFAULT_SIZE = 256;

    private byte[] data;
    private int rpos;
    private int wpos;

    /**
     * Allocates a buffer for writing purposes with {@value #DEFAULT_SIZE} bytes
     */
    public ByteArrayBuffer() {
        this(DEFAULT_SIZE, false);
    }

    /**
     * Allocates a buffer for writing purposes
     *
     * @param size Initial buffer size - <B>Note:</B> it is <U>rounded</U> to the closest power of 2 that is greater or
     *             equal to it.
     * @see        #ByteArrayBuffer(int, boolean)
     */
    public ByteArrayBuffer(int size) {
        this(size, true);
    }

    /**
     * Allocates a buffer for writing purposes
     *
     * @param size     Initial buffer size
     * @param roundOff Whether to round it to closest power of 2 that is greater or equal to the specified size
     */
    public ByteArrayBuffer(int size, boolean roundOff) {
        this(new byte[roundOff ? BufferUtils.getNextPowerOf2(size) : size], false);
    }

    /**
     * Wraps data bytes for reading
     *
     * @param data Data bytes to read from
     * @see        #ByteArrayBuffer(byte[], boolean)
     */
    public ByteArrayBuffer(byte[] data) {
        this(data, 0, data.length, true);
    }

    /**
     * @param data Data bytes to use
     * @param read Whether the data bytes are for reading or writing
     */
    public ByteArrayBuffer(byte[] data, boolean read) {
        this(data, 0, data.length, read);
    }

    /**
     * Wraps data bytes for reading
     *
     * @param data Data bytes to read from
     * @param off  Offset to read from
     * @param len  Available bytes from given offset
     * @see        #ByteArrayBuffer(byte[], int, int, boolean)
     */
    public ByteArrayBuffer(byte[] data, int off, int len) {
        this(data, off, len, true);
    }

    /**
     * @param data Data bytes to use
     * @param off  Offset to read/write (according to <tt>read</tt> parameter)
     * @param len  Available bytes from given offset
     * @param read Whether the data bytes are for reading or writing
     */
    public ByteArrayBuffer(byte[] data, int off, int len, boolean read) {
        if ((off < 0) || (len < 0)) {
            throw new IndexOutOfBoundsException("Invalid offset(" + off + ")/length(" + len + ")");
        }
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
    public byte[] getBytesConsumed() {
        byte[] consumed = new byte[rpos];
        System.arraycopy(data, 0, consumed, 0, rpos);
        return consumed;
    }

    @Override
    public byte rawByte(int pos) {
        return data[pos];
    }

    @Override
    public long rawUInt(int pos) {
        return BufferUtils.getUInt(data, pos, Integer.BYTES);
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
    public Buffer clear(boolean wipeData) {
        rpos = 0;
        wpos = 0;

        if (wipeData) {
            Arrays.fill(data, (byte) 0);
        }

        return this;
    }

    @Override
    public byte getByte() {
        ensureAvailable(Byte.BYTES);
        return data[rpos++];
    }

    @Override
    public void putByte(byte b) {
        ensureCapacity(Byte.BYTES);
        data[wpos++] = b;
    }

    @Override
    public int putBuffer(Readable buffer, boolean expand) {
        int required = expand ? buffer.available() : Math.min(buffer.available(), capacity());
        ensureCapacity(required);
        buffer.getRawBytes(data, wpos, required);
        wpos += required;
        return required;
    }

    @Override
    public void putBuffer(ByteBuffer buffer) {
        int required = buffer.remaining();
        ensureCapacity(required + Integer.SIZE);
        putInt(required);
        buffer.get(data, wpos, required);
        wpos += required;
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
        Objects.requireNonNull(charset, "No charset specified");

        int reqLen = getInt();
        int len = ensureAvailable(reqLen);
        String s = new String(data, rpos, len, charset);
        rpos += len;
        return s;
    }

    @Override
    public void getRawBytes(byte[] buf, int off, int len) {
        ensureAvailable(len);
        copyRawBytes(0, buf, off, len);
        rpos += len;
    }

    @Override
    protected void copyRawBytes(int offset, byte[] buf, int pos, int len) {
        if ((offset < 0) || (pos < 0) || (len < 0)) {
            throw new IndexOutOfBoundsException(
                    "Invalid offset(" + offset + ")/position(" + pos + ")/length(" + len + ") required");
        }
        System.arraycopy(data, rpos + offset, buf, pos, len);
    }

    @Override
    public Buffer ensureCapacity(int capacity, IntUnaryOperator growthFactor) {
        ValidateUtils.checkTrue(capacity >= 0, "Negative capacity requested: %d", capacity);

        int maxSize = size();
        int curPos = wpos();
        int remaining = maxSize - curPos;
        if (remaining < capacity) {
            int minimum = curPos + capacity;
            int actual = growthFactor.applyAsInt(minimum);
            if (actual < minimum) {
                throw new IllegalStateException(
                        "ensureCapacity(" + capacity + ") actual (" + actual + ") below min. (" + minimum + ")");
            }
            byte[] tmp = new byte[actual];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }

        return this;
    }

    @Override
    protected int size() {
        return data.length;
    }

    /**
     * Creates a compact buffer (i.e., one that starts at offset zero) containing a <U>copy</U> of the original data
     *
     * @param  data The original data buffer
     * @return      A {@link ByteArrayBuffer} containing a <U>copy</U> of the original data starting at zero read
     *              position
     * @see         #getCompactClone(byte[], int, int)
     */
    public static ByteArrayBuffer getCompactClone(byte[] data) {
        return getCompactClone(data, 0, NumberUtils.length(data));
    }

    /**
     * Creates a compact buffer (i.e., one that starts at offset zero) containing a <U>copy</U> of the original data
     *
     * @param  data   The original data buffer
     * @param  offset The offset of the valid data in the buffer
     * @param  len    The size (in bytes) of of the valid data in the buffer
     * @return        A {@link ByteArrayBuffer} containing a <U>copy</U> of the original data starting at zero read
     *                position
     */
    public static ByteArrayBuffer getCompactClone(byte[] data, int offset, int len) {
        byte[] clone = (len > 0) ? new byte[len] : GenericUtils.EMPTY_BYTE_ARRAY;
        if (len > 0) {
            System.arraycopy(data, offset, clone, 0, len);
        }

        return new ByteArrayBuffer(clone, true);
    }
}
