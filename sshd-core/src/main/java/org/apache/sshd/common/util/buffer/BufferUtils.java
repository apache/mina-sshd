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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class BufferUtils {

    public static final char DEFAULT_HEX_SEPARATOR = ' ';

    public static final char EMPTY_HEX_SEPARATOR = '\0';

    public static final String HEX_DIGITS = "0123456789abcdef";

    public static final Int2IntFunction DEFAULT_BUFFER_GROWTH_FACTOR =
        new Int2IntFunction() {
            @Override
            public int apply(int value) {
                return getNextPowerOf2(value);
            }
        };

    /**
     * Private Constructor
     */
    private BufferUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static String printHex(byte... array) {
        return printHex(array, 0, GenericUtils.length(array));
    }

    public static String printHex(char sep, byte... array) {
        return printHex(array, 0, GenericUtils.length(array), sep);
    }

    public static String printHex(byte[] array, int offset, int len) {
        return printHex(array, offset, len, DEFAULT_HEX_SEPARATOR);
    }

    public static String printHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder(len * 3 /* 2 HEX + sep */);
        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if ((sb.length() > 0) && (sep != EMPTY_HEX_SEPARATOR)) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb.toString();
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param input The {@link InputStream}
     * @param buf   Work buffer to use
     * @return The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in
     * @see #readInt(InputStream, byte[], int, int)
     */
    public static int readInt(InputStream input, byte[] buf) throws IOException {
        return readInt(input, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param input  The {@link InputStream}
     * @param buf    Work buffer to use
     * @param offset Offset in buffer to us
     * @param len    Available length - must have at least 4 bytes available
     * @return The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in
     *                     work buffer
     * @see #readUInt(InputStream, byte[], int, int)
     */
    public static int readInt(InputStream input, byte[] buf, int offset, int len) throws IOException {
        return (int) readUInt(input, buf, offset, len);
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param input The {@link InputStream}
     * @param buf   Work buffer to use
     * @return The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in
     * @see #readUInt(InputStream, byte[], int, int)
     */
    public static long readUInt(InputStream input, byte[] buf) throws IOException {
        return readUInt(input, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param input  The {@link InputStream}
     * @param buf    Work buffer to use
     * @param offset Offset in buffer to us
     * @param len    Available length - must have at least 4 bytes available
     * @return The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in
     *                     work buffer
     * @see #getUInt(byte[], int, int)
     */
    public static long readUInt(InputStream input, byte[] buf, int offset, int len) throws IOException {
        try {
            // TODO use Integer.BYTES for JDK-8
            if (len < (Integer.SIZE / Byte.SIZE)) {
                throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
            }

            // TODO use Integer.BYTES for JDK-8
            IoUtils.readFully(input, buf, offset, Integer.SIZE / Byte.SIZE);
            return getUInt(buf, offset, len);
        } catch (IllegalArgumentException e) {
            throw new StreamCorruptedException(e.getMessage());
        }
    }

    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     *            format. <B>Note:</B> if more than 4 bytes are available, then only the
     *            <U>first</U> 4 bytes in the buffer will be used
     * @return The result as a {@code long} whose 32 high-order bits are zero
     * @see #getUInt(byte[], int, int)
     */
    public static long getUInt(byte... buf) {
        return getUInt(buf, 0, GenericUtils.length(buf));
    }

    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     *            format.
     * @param off The offset of the data in the buffer
     * @param len The available data length. <B>Note:</B> if more than 4 bytes
     *            are available, then only the <U>first</U> 4 bytes in the buffer will be
     *            used (starting at the specified <tt>offset</tt>)
     * @return The result as a {@code long} whose 32 high-order bits are zero
     */
    public static long getUInt(byte[] buf, int off, int len) {
        // TODO use Integer.BYTES for JDK-8
        if (len < (Integer.SIZE / Byte.SIZE)) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        long l = (buf[off] << 24) & 0xff000000L;
        l |= (buf[off + 1] << 16) & 0x00ff0000L;
        l |= (buf[off + 2] << 8) & 0x0000ff00L;
        l |= (buf[off + 3]) & 0x000000ffL;
        return l;
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param output The {@link OutputStream} to write the value
     * @param value  The 32-bit value
     * @param buf    A work buffer to use - must have enough space to contain 4 bytes
     * @throws IOException If failed to write the value or work buffer to small
     * @see #writeInt(OutputStream, int, byte[], int, int)
     */
    public static void writeInt(OutputStream output, int value, byte[] buf) throws IOException {
        writeUInt(output, value, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param output The {@link OutputStream} to write the value
     * @param value  The 32-bit value
     * @param buf    A work buffer to use - must have enough space to contain 4 bytes
     * @param off    The offset to write the value
     * @param len    The available space
     * @throws IOException If failed to write the value or work buffer to small
     * @see #writeUInt(OutputStream, long, byte[], int, int)
     */
    public static void writeInt(OutputStream output, int value, byte[] buf, int off, int len) throws IOException {
        writeUInt(output, value & 0xFFFFFFFFL, buf, off, len);
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param output The {@link OutputStream} to write the value
     * @param value  The 32-bit value
     * @param buf    A work buffer to use - must have enough space to contain 4 bytes
     * @throws IOException If failed to write the value or work buffer to small
     * @see #writeUInt(OutputStream, long, byte[], int, int)
     */
    public static void writeUInt(OutputStream output, long value, byte[] buf) throws IOException {
        writeUInt(output, value, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param output The {@link OutputStream} to write the value
     * @param value  The 32-bit value
     * @param buf    A work buffer to use - must have enough space to contain 4 bytes
     * @param off    The offset to write the value
     * @param len    The available space
     * @throws IOException If failed to write the value or work buffer to small
     * @see #putUInt(long, byte[], int, int)
     */
    public static void writeUInt(OutputStream output, long value, byte[] buf, int off, int len) throws IOException {
        try {
            int writeLen = putUInt(value, buf, off, len);
            output.write(buf, off, writeLen);
        } catch (IllegalArgumentException e) {
            throw new StreamCorruptedException(e.getMessage());
        }
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param value The 32-bit value
     * @param buf   The buffer
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     * @see #putUInt(long, byte[], int, int)
     */
    public static int putUInt(long value, byte[] buf) {
        return putUInt(value, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param value The 32-bit value
     * @param buf   The buffer
     * @param off   The offset to write the value
     * @param len   The available space
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     */
    public static int putUInt(long value, byte[] buf, int off, int len) {
        // TODO use Integer.BYTES for JDK-8
        if (len < Integer.SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        buf[off] = (byte) ((value >> 24) & 0xFF);
        buf[off + 1] = (byte) ((value >> 16) & 0xFF);
        buf[off + 2] = (byte) ((value >> 8) & 0xFF);
        buf[off + 3] = (byte) (value & 0xFF);

        return Integer.SIZE / Byte.SIZE;
    }

    public static boolean equals(byte[] a1, byte[] a2) {
        int len1 = GenericUtils.length(a1);
        int len2 = GenericUtils.length(a2);
        if (len1 != len2) {
            return false;
        } else {
            return equals(a1, 0, a2, 0, len1);
        }
    }

    public static boolean equals(byte[] a1, int a1Offset, byte[] a2, int a2Offset, int length) {
        int len1 = GenericUtils.length(a1);
        int len2 = GenericUtils.length(a2);
        if ((len1 < (a1Offset + length)) || (len2 < (a2Offset + length))) {
            return false;
        }

        while (length-- > 0) {
            if (a1[a1Offset++] != a2[a2Offset++]) {
                return false;
            }
        }
        return true;
    }

    public static int getNextPowerOf2(int i) {
        // for 0-7 return 8
        if (i < Byte.SIZE) {
            return Byte.SIZE;
        }

        int j = 1;
        while (j < i) {
            j <<= 1;
        }
        return j;
    }

    /**
     * Used for encodings where we don't know the data length before adding it
     * to the buffer. The idea is to place a 32-bit &quot;placeholder&quot;,
     * encode the data and then return back to the placeholder and update the
     * length. The method calculates the encoded data length, moves the write
     * position to the specified placeholder position, updates the length value
     * and then moves the write position it back to its original value.
     *
     * @param buffer The {@link Buffer}
     * @param lenPos The offset in the buffer where the length placeholder is
     *               to be update - <B>Note:</B> assumption is that the encoded data starts
     *               <U>immediately</U> after the placeholder
     * @return The amount of data that has been encoded
     */
    public static int updateLengthPlaceholder(Buffer buffer, int lenPos) {
        int startPos = lenPos + (Integer.SIZE / Byte.SIZE);
        int endPos = buffer.wpos();
        int dataLength = endPos - startPos;
        // NOTE: although data length is defined as UINT32, we do not expected sizes above Integer.MAX_VALUE
        ValidateUtils.checkTrue(dataLength >= 0, "Illegal data length: %d", dataLength);
        buffer.wpos(lenPos);
        buffer.putInt(dataLength);
        buffer.wpos(endPos);
        return dataLength;
    }

    /**
     * Updates a 32-bit &quot;placeholder&quot; location for data length - moves
     * the write position to the specified placeholder position, updates the length
     * value and then moves the write position it back to its original value.
     *
     * @param buffer     The {@link Buffer}
     * @param lenPos     The offset in the buffer where the length placeholder is
     *                   to be update - <B>Note:</B> assumption is that the encoded data starts
     *                   <U>immediately</U> after the placeholder
     * @param dataLength The length to update
     */
    public static void updateLengthPlaceholder(Buffer buffer, int lenPos, int dataLength) {
        int curPos = buffer.wpos();
        buffer.wpos(lenPos);
        buffer.putInt(dataLength);
        buffer.wpos(curPos);
    }

    /**
     * Invokes {@link Buffer#clear()}
     *
     * @param <B>    The generic buffer type
     * @param buffer A {@link Buffer} instance - ignored if {@code null}
     * @return The same as the input instance
     */
    public static <B extends Buffer> B clear(B buffer) {
        if (buffer != null) {
            buffer.clear();
        }

        return buffer;
    }
}
