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
import java.math.BigInteger;
import java.util.function.IntUnaryOperator;
import java.util.logging.Level;

import org.apache.sshd.common.CommonModuleProperties;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.SimplifiedLog;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class BufferUtils {
    public static final char DEFAULT_HEX_SEPARATOR = ' ';
    public static final char EMPTY_HEX_SEPARATOR = '\0';
    public static final String HEX_DIGITS = "0123456789abcdef";

    public static final Level DEFAULT_HEXDUMP_LEVEL = Level.FINEST;

    public static final IntUnaryOperator DEFAULT_BUFFER_GROWTH_FACTOR = BufferUtils::getNextPowerOf2;

    /**
     * Maximum value of a {@code uint32} field
     */
    public static final long MAX_UINT32_VALUE = 0x0FFFFFFFFL;

    /**
     * Maximum value of a {@code uint8} field
     */
    public static final int MAX_UINT8_VALUE = 0x0FF;

    /**
     * Private Constructor
     */
    private BufferUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static void dumpHex(
            SimplifiedLog logger, Level level, String prefix, PropertyResolver resolver, char sep, byte... data) {
        dumpHex(logger, level, prefix, resolver, sep, data, 0, NumberUtils.length(data));
    }

    public static void dumpHex(
            SimplifiedLog logger, Level level, String prefix, PropertyResolver resolver,
            char sep, byte[] data, int offset, int len) {
        dumpHex(logger, level, prefix, sep,
                CommonModuleProperties.HEXDUMP_CHUNK_SIZE.getRequired(resolver),
                data, offset, len);
    }

    public static void dumpHex(
            SimplifiedLog logger, Level level, String prefix, char sep, int chunkSize, byte... data) {
        dumpHex(logger, level, prefix, sep, chunkSize, data, 0, NumberUtils.length(data));
    }

    public static void dumpHex(
            SimplifiedLog logger, Level level, String prefix, char sep,
            int chunkSize, byte[] data, int offset, int len) {
        if ((logger == null) || (level == null) || (!logger.isEnabledLevel(level))) {
            return;
        }

        StringBuilder sb = new StringBuilder(chunkSize * 3 /* HEX */ + prefix.length() + Long.SIZE /* some extra */);
        sb.append(prefix);
        for (int remainLen = len, chunkIndex = 1, curOffset = offset, totalLen = 0; remainLen > 0; chunkIndex++) {
            sb.setLength(prefix.length()); // reset for next chunk

            sb.append(" [chunk #").append(chunkIndex).append(']');

            int dumpSize = Math.min(chunkSize, remainLen);
            totalLen += dumpSize;
            sb.append('(').append(totalLen).append('/').append(len).append(')');

            try {
                appendHex(sb.append(' '), data, curOffset, dumpSize, sep);
            } catch (IOException e) { // unexpected
                sb.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
            }

            // Pad the last (incomplete) line to align its data view
            for (int index = dumpSize; index < chunkSize; index++) {
                if (sep != EMPTY_HEX_SEPARATOR) {
                    sb.append(' ');
                }
                sb.append("  ");
            }

            sb.append("    ");
            for (int pos = curOffset, l = 0; l < dumpSize; pos++, l++) {
                int b = data[pos] & 0xFF;
                if ((b > ' ') && (b < 0x7E)) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }

            logger.log(level, sb.toString());
            remainLen -= dumpSize;
            curOffset += dumpSize;
        }
    }

    public static String toHex(byte... array) {
        return toHex(array, 0, NumberUtils.length(array));
    }

    public static String toHex(char sep, byte... array) {
        return toHex(array, 0, NumberUtils.length(array), sep);
    }

    public static String toHex(byte[] array, int offset, int len) {
        return toHex(array, offset, len, DEFAULT_HEX_SEPARATOR);
    }

    public static String toHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        try {
            return appendHex(new StringBuilder(len * 3 /* 2 HEX + sep */), array, offset, len, sep).toString();
        } catch (IOException e) { // unexpected
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static <A extends Appendable> A appendHex(A sb, char sep, byte... array) throws IOException {
        return appendHex(sb, array, 0, NumberUtils.length(array), sep);
    }

    public static <A extends Appendable> A appendHex(
            A sb, byte[] array, int offset, int len, char sep)
            throws IOException {
        if (len <= 0) {
            return sb;
        }

        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if ((curOffset > offset) && (sep != EMPTY_HEX_SEPARATOR)) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb;
    }

    /**
     * @param  separator                The separator between the HEX values - may be {@link #EMPTY_HEX_SEPARATOR}
     * @param  csq                      The {@link CharSequence} containing the HEX encoded bytes
     * @return                          The decoded bytes
     * @throws IllegalArgumentException If invalid HEX sequence length
     * @throws NumberFormatException    If invalid HEX characters found
     * @see                             #decodeHex(char, CharSequence, int, int)
     */
    public static byte[] decodeHex(char separator, CharSequence csq) {
        return decodeHex(separator, csq, 0, GenericUtils.length(csq));
    }

    /**
     * @param  separator                The separator between the HEX values - may be {@link #EMPTY_HEX_SEPARATOR}
     * @param  csq                      The {@link CharSequence} containing the HEX encoded bytes
     * @param  start                    Start offset of the HEX sequence (inclusive)
     * @param  end                      End offset of the HEX sequence (exclusive)
     * @return                          The decoded bytes
     * @throws IllegalArgumentException If invalid HEX sequence length
     * @throws NumberFormatException    If invalid HEX characters found
     */
    public static byte[] decodeHex(char separator, CharSequence csq, int start, int end) {
        int len = end - start;
        ValidateUtils.checkTrue(len >= 0, "Bad HEX sequence length: %d", len);
        if (len == 0) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        int delta = 2;
        byte[] bytes;
        if (separator != EMPTY_HEX_SEPARATOR) {
            // last character cannot be the separator
            ValidateUtils.checkTrue((len % 3) == 2, "Invalid separated HEX sequence length: %d", len);
            bytes = new byte[(len + 1) / 3];
            delta++;
        } else {
            ValidateUtils.checkTrue((len & 0x01) == 0, "Invalid contiguous HEX sequence length: %d", len);
            bytes = new byte[len >>> 1];
        }

        int writeLen = 0;
        for (int curPos = start; curPos < end; curPos += delta, writeLen++) {
            bytes[writeLen] = fromHex(csq.charAt(curPos), csq.charAt(curPos + 1));
        }
        assert writeLen == bytes.length;

        return bytes;
    }

    /**
     * @param  <S>                      The {@link OutputStream} generic type
     * @param  stream                   The target {@link OutputStream}
     * @param  separator                The separator between the HEX values - may be {@link #EMPTY_HEX_SEPARATOR}
     * @param  csq                      The {@link CharSequence} containing the HEX encoded bytes
     * @return                          The number of bytes written to the stream
     * @throws IOException              If failed to write
     * @throws IllegalArgumentException If invalid HEX sequence length
     * @throws NumberFormatException    If invalid HEX characters found
     * @see                             #decodeHex(OutputStream, char, CharSequence, int, int)
     */
    public static <S extends OutputStream> int decodeHex(
            S stream, char separator, CharSequence csq)
            throws IOException {
        return decodeHex(stream, separator, csq, 0, GenericUtils.length(csq));
    }

    /**
     * @param  <S>                      The {@link OutputStream} generic type
     * @param  stream                   The target {@link OutputStream}
     * @param  separator                The separator between the HEX values - may be {@link #EMPTY_HEX_SEPARATOR}
     * @param  csq                      The {@link CharSequence} containing the HEX encoded bytes
     * @param  start                    Start offset of the HEX sequence (inclusive)
     * @param  end                      End offset of the HEX sequence (exclusive)
     * @return                          The number of bytes written to the stream
     * @throws IOException              If failed to write
     * @throws IllegalArgumentException If invalid HEX sequence length
     * @throws NumberFormatException    If invalid HEX characters found
     */
    public static <S extends OutputStream> int decodeHex(
            S stream, char separator, CharSequence csq, int start, int end)
            throws IOException {
        int len = end - start;
        ValidateUtils.checkTrue(len >= 0, "Bad HEX sequence length: %d", len);

        int delta = 2;
        if (separator != EMPTY_HEX_SEPARATOR) {
            // last character cannot be the separator
            ValidateUtils.checkTrue((len % 3) == 2, "Invalid separated HEX sequence length: %d", len);
            delta++;
        } else {
            ValidateUtils.checkTrue((len & 0x01) == 0, "Invalid contiguous HEX sequence length: %d", len);
        }

        int writeLen = 0;
        for (int curPos = start; curPos < end; curPos += delta, writeLen++) {
            stream.write(fromHex(csq.charAt(curPos), csq.charAt(curPos + 1)) & 0xFF);
        }

        return writeLen;
    }

    public static byte fromHex(char hi, char lo) throws NumberFormatException {
        int hiValue = HEX_DIGITS.indexOf(((hi >= 'A') && (hi <= 'F')) ? ('a' + (hi - 'A')) : hi);
        int loValue = HEX_DIGITS.indexOf(((lo >= 'A') && (lo <= 'F')) ? ('a' + (lo - 'A')) : lo);
        if ((hiValue < 0) || (loValue < 0)) {
            throw new NumberFormatException("fromHex(" + new String(new char[] { hi, lo }) + ") non-HEX characters");
        }

        return (byte) ((hiValue << 4) + loValue);
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param  input       The {@link InputStream}
     * @param  buf         Work buffer to use
     * @return             The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in work buffer
     * @see                #readInt(InputStream, byte[], int, int)
     */
    public static int readInt(InputStream input, byte[] buf) throws IOException {
        return readInt(input, buf, 0, NumberUtils.length(buf));
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param  input       The {@link InputStream}
     * @param  buf         Work buffer to use
     * @param  offset      Offset in buffer to us
     * @param  len         Available length - must have at least 4 bytes available
     * @return             The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in work buffer
     * @see                #readUInt(InputStream, byte[], int, int)
     */
    public static int readInt(InputStream input, byte[] buf, int offset, int len) throws IOException {
        return (int) readUInt(input, buf, offset, len);
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param  input       The {@link InputStream}
     * @param  buf         Work buffer to use
     * @return             The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in work buffer
     * @see                #readUInt(InputStream, byte[], int, int)
     */
    public static long readUInt(InputStream input, byte[] buf) throws IOException {
        return readUInt(input, buf, 0, NumberUtils.length(buf));
    }

    /**
     * Read a 32-bit value in network order
     *
     * @param  input       The {@link InputStream}
     * @param  buf         Work buffer to use
     * @param  offset      Offset in buffer to us
     * @param  len         Available length - must have at least 4 bytes available
     * @return             The read 32-bit value
     * @throws IOException If failed to read 4 bytes or not enough room in work buffer
     * @see                #getUInt(byte[], int, int)
     */
    public static long readUInt(InputStream input, byte[] buf, int offset, int len) throws IOException {
        try {
            if (len < Integer.BYTES) {
                throw new IllegalArgumentException(
                        "Not enough data for a UINT: required=" + Integer.BYTES + ", available=" + len);
            }

            IoUtils.readFully(input, buf, offset, Integer.BYTES);
            return getUInt(buf, offset, len);
        } catch (RuntimeException | Error e) {
            throw new StreamCorruptedException(
                    "Failed (" + e.getClass().getSimpleName() + ")"
                                               + " to read UINT value: " + e.getMessage());
        }
    }

    /**
     * @param  buf A buffer holding a 32-bit unsigned integer in <B>big endian</B> format. <B>Note:</B> if more than 4
     *             bytes are available, then only the <U>first</U> 4 bytes in the buffer will be used
     * @return     The result as a {@code long} whose 32 high-order bits are zero
     * @see        #getUInt(byte[], int, int)
     */
    public static long getUInt(byte... buf) {
        return getUInt(buf, 0, NumberUtils.length(buf));
    }

    /**
     * @param  buf A buffer holding a 32-bit unsigned integer in <B>big endian</B> format.
     * @param  off The offset of the data in the buffer
     * @param  len The available data length. <B>Note:</B> if more than 4 bytes are available, then only the
     *             <U>first</U> 4 bytes in the buffer will be used (starting at the specified <tt>offset</tt>)
     * @return     The result as a {@code long} whose 32 high-order bits are zero
     */
    public static long getUInt(byte[] buf, int off, int len) {
        if (len < Integer.BYTES) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + Integer.BYTES + ", available=" + len);
        }

        long l = (buf[off] << 24) & 0xff000000L;
        l |= (buf[off + 1] << 16) & 0x00ff0000L;
        l |= (buf[off + 2] << 8) & 0x0000ff00L;
        l |= (buf[off + 3]) & 0x000000ffL;
        return l;
    }

    public static long getLong(byte[] buf, int off, int len) {
        if (len < Long.BYTES) {
            throw new IllegalArgumentException("Not enough data for a long: required=" + Long.BYTES + ", available=" + len);
        }

        long l = (long) buf[off] << 56;
        l |= ((long) buf[off + 1] & 0xff) << 48;
        l |= ((long) buf[off + 2] & 0xff) << 40;
        l |= ((long) buf[off + 3] & 0xff) << 32;
        l |= ((long) buf[off + 4] & 0xff) << 24;
        l |= ((long) buf[off + 5] & 0xff) << 16;
        l |= ((long) buf[off + 6] & 0xff) << 8;
        l |= (long) buf[off + 7] & 0xff;

        return l;
    }

    public static BigInteger fromMPIntBytes(byte[] mpInt) {
        if (NumberUtils.isEmpty(mpInt)) {
            return null;
        }

        if ((mpInt[0] & 0x80) != 0) {
            return new BigInteger(0, mpInt);
        } else {
            return new BigInteger(mpInt);
        }
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  output      The {@link OutputStream} to write the value
     * @param  value       The 32-bit value
     * @param  buf         A work buffer to use - must have enough space to contain 4 bytes
     * @throws IOException If failed to write the value or work buffer too small
     * @see                #writeInt(OutputStream, int, byte[], int, int)
     */
    public static void writeInt(OutputStream output, int value, byte[] buf) throws IOException {
        writeUInt(output, value, buf, 0, NumberUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  output      The {@link OutputStream} to write the value
     * @param  value       The 32-bit value
     * @param  buf         A work buffer to use - must have enough space to contain 4 bytes
     * @param  off         The offset to write the value
     * @param  len         The available space
     * @throws IOException If failed to write the value or work buffer too small
     * @see                #writeUInt(OutputStream, long, byte[], int, int)
     */
    public static void writeInt(
            OutputStream output, int value, byte[] buf, int off, int len)
            throws IOException {
        writeUInt(output, value & 0xFFFFFFFFL, buf, off, len);
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  output      The {@link OutputStream} to write the value
     * @param  value       The 32-bit value
     * @param  buf         A work buffer to use - must have enough space to contain 4 bytes
     * @throws IOException If failed to write the value or work buffer too small
     * @see                #writeUInt(OutputStream, long, byte[], int, int)
     */
    public static void writeUInt(OutputStream output, long value, byte[] buf) throws IOException {
        writeUInt(output, value, buf, 0, NumberUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  output      The {@link OutputStream} to write the value
     * @param  value       The 32-bit value
     * @param  buf         A work buffer to use - must have enough space to contain 4 bytes
     * @param  off         The offset to write the value
     * @param  len         The available space
     * @throws IOException If failed to write the value or work buffer to small
     * @see                #putUInt(long, byte[], int, int)
     */
    public static void writeUInt(
            OutputStream output, long value, byte[] buf, int off, int len)
            throws IOException {
        try {
            int writeLen = putUInt(value, buf, off, len);
            output.write(buf, off, writeLen);
        } catch (RuntimeException | Error e) {
            throw new StreamCorruptedException(
                    "Failed (" + e.getClass().getSimpleName() + ")"
                                               + " to write UINT value=" + value + ": " + e.getMessage());
        }
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  value                    The 32-bit value
     * @param  buf                      The buffer
     * @return                          The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     * @see                             #putUInt(long, byte[], int, int)
     */
    public static int putUInt(long value, byte[] buf) {
        return putUInt(value, buf, 0, NumberUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  value                    The 32-bit value
     * @param  buf                      The buffer
     * @param  off                      The offset to write the value
     * @param  len                      The available space
     * @return                          The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     */
    public static int putUInt(long value, byte[] buf, int off, int len) {
        if (len < Integer.BYTES) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + Integer.BYTES + ", available=" + len);
        }

        buf[off] = (byte) ((value >> 24) & 0xFF);
        buf[off + 1] = (byte) ((value >> 16) & 0xFF);
        buf[off + 2] = (byte) ((value >> 8) & 0xFF);
        buf[off + 3] = (byte) (value & 0xFF);

        return Integer.BYTES;
    }

    public static int putLong(long value, byte[] buf, int off, int len) {
        if (len < Long.BYTES) {
            throw new IllegalArgumentException("Not enough data for a long: required=" + Long.BYTES + ", available=" + len);
        }

        buf[off] = (byte) (value >> 56);
        buf[off + 1] = (byte) (value >> 48);
        buf[off + 2] = (byte) (value >> 40);
        buf[off + 3] = (byte) (value >> 32);
        buf[off + 4] = (byte) (value >> 24);
        buf[off + 5] = (byte) (value >> 16);
        buf[off + 6] = (byte) (value >> 8);
        buf[off + 7] = (byte) value;

        return Long.BYTES;
    }

    /**
     * Compares the contents of 2 arrays of bytes - <B>Note:</B> do not use it to execute security related comparisons
     * (e.g. MACs) since the method leaks timing information. Use {@code Mac#equals} method instead.
     *
     * @param  a1 1st array
     * @param  a2 2nd array
     * @return    {@code true} if all bytes in the compared arrays are equal
     */
    public static boolean equals(byte[] a1, byte[] a2) {
        int len1 = NumberUtils.length(a1);
        int len2 = NumberUtils.length(a2);
        if (len1 != len2) {
            return false;
        } else {
            return equals(a1, 0, a2, 0, len1);
        }
    }

    /**
     * Compares the contents of 2 arrays of bytes - <B>Note:</B> do not use it to execute security related comparisons
     * (e.g. MACs) since the method leaks timing information. Use {@code Mac#equals} method instead.
     *
     * @param  a1       1st array
     * @param  a1Offset Offset to start comparing in 1st array
     * @param  a2       2nd array
     * @param  a2Offset Offset to start comparing in 2nd array
     * @param  length   Number of bytes to compare
     * @return          {@code true} if all bytes in the compared arrays are equal when compared from the specified
     *                  offsets and up to specified length
     */
    @SuppressWarnings("PMD.AssignmentInOperand")
    public static boolean equals(byte[] a1, int a1Offset, byte[] a2, int a2Offset, int length) {
        int len1 = NumberUtils.length(a1);
        int len2 = NumberUtils.length(a2);
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

    public static int getNextPowerOf2(int value) {
        // for 0-7 return 8
        return (value < Byte.SIZE)
                ? Byte.SIZE
                : (value > (1 << 30))
                        ? value
                : NumberUtils.getNextPowerOf2(value);
    }

    /**
     * Used for encodings where we don't know the data length before adding it to the buffer. The idea is to place a
     * 32-bit &quot;placeholder&quot;, encode the data and then return back to the placeholder and update the length.
     * The method calculates the encoded data length, moves the write position to the specified placeholder position,
     * updates the length value and then moves the write position it back to its original value.
     *
     * @param  buffer The {@link Buffer}
     * @param  lenPos The offset in the buffer where the length placeholder is to be update - <B>Note:</B> assumption is
     *                that the encoded data starts <U>immediately</U> after the placeholder
     * @return        The amount of data that has been encoded
     */
    public static int updateLengthPlaceholder(Buffer buffer, int lenPos) {
        int startPos = lenPos + Integer.BYTES;
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
     * Updates a 32-bit &quot;placeholder&quot; location for data length - moves the write position to the specified
     * placeholder position, updates the length value and then moves the write position it back to its original value.
     *
     * @param buffer     The {@link Buffer}
     * @param lenPos     The offset in the buffer where the length placeholder is to be update - <B>Note:</B> assumption
     *                   is that the encoded data starts <U>immediately</U> after the placeholder
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
     * @param  <B>    The generic buffer type
     * @param  buffer A {@link Buffer} instance - ignored if {@code null}
     * @return        The same as the input instance
     */
    public static <B extends Buffer> B clear(B buffer) {
        if (buffer != null) {
            buffer.clear();
        }

        return buffer;
    }

    public static long validateInt32Value(long value, String message) {
        ValidateUtils.checkTrue(isValidInt32Value(value), message, value);
        return value;
    }

    public static long validateInt32Value(long value, String format, Object arg) {
        ValidateUtils.checkTrue(isValidInt32Value(value), format, arg);
        return value;
    }

    public static long validateInt32Value(long value, String format, Object... args) {
        ValidateUtils.checkTrue(isValidInt32Value(value), format, args);
        return value;
    }

    public static boolean isValidInt32Value(long value) {
        return (value >= Integer.MIN_VALUE) && (value <= Integer.MAX_VALUE);
    }

    public static long validateUint32Value(long value, String message) {
        ValidateUtils.checkTrue(isValidUint32Value(value), message, value);
        return value;
    }

    public static long validateUint32Value(long value, String format, Object arg) {
        ValidateUtils.checkTrue(isValidUint32Value(value), format, arg);
        return value;
    }

    public static long validateUint32Value(long value, String format, Object... args) {
        ValidateUtils.checkTrue(isValidUint32Value(value), format, args);
        return value;
    }

    public static boolean isValidUint32Value(long value) {
        return (value >= 0L) && (value <= MAX_UINT32_VALUE);
    }
}
