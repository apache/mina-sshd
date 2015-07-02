/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util.buffer;

import org.apache.sshd.common.util.GenericUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BufferUtils {

    public static String printHex(byte ... array) {
        return printHex(array, 0, GenericUtils.length(array));
    }

    public static String printHex(char sep, byte ... array) {
        return printHex(array, 0, GenericUtils.length(array), sep);
    }

    public static String printHex(byte[] array, int offset, int len) {
        return printHex(array, offset, len, ' ');
    }

    public static final String  HEX_DIGITS="0123456789abcdef";

    public static String printHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder(len * 3 /* 2 HEX + sep */);
        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb.toString();
    }

    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     * format. <B>Note:</B> if more than 4 bytes are available, then only the
     * <U>first</U> 4 bytes in the buffer will be used
     * @return The result as a {@code long} whose 32 high-order bits are zero
     * @see #getUInt(byte[], int, int)
     */
    public static long getUInt(byte ... buf) {
        return getUInt(buf, 0, GenericUtils.length(buf));
    }
    
    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     * format.
     * @param off The offset of the data in the buffer
     * @param len The available data length. <B>Note:</B> if more than 4 bytes
     * are available, then only the <U>first</U> 4 bytes in the buffer will be
     * used (starting at the specified <tt>offset</tt>)
     * @return The result as a {@code long} whose 32 high-order bits are zero
     */
    public static long getUInt(byte[] buf, int off, int len) {
        // TODO use Integer.BYTES for JDK-8
        if (len < (Integer.SIZE / Byte.SIZE)) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        return ((buf[off] << 24) & 0xff000000L)
             | ((buf[off + 1] << 16) & 0x00ff0000L)
             | ((buf[off + 2] <<  8) & 0x0000ff00L)
             | ((buf[off + 3]      ) & 0x000000ffL)
             ;
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     * @param value The 32-bit value 
     * @param buf The buffer
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     * @see #putUInt(long, byte[], int, int)
     */
    public static int putUInt(long value, byte[] buf) {
        return putUInt(value, buf, 0, GenericUtils.length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     * @param value The 32-bit value 
     * @param buf The buffer
     * @param off The offset to write the value
     * @param len The available space
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     */
    public static int putUInt(long value, byte[] buf, int off, int len) {
        // TODO use Integer.BYTES for JDK-8
        if (len < (Integer.SIZE / Byte.SIZE)) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        buf[off]     = (byte) ((value >> 24) & 0xFF);
        buf[off + 1] = (byte) ((value >> 16) & 0xFF);
        buf[off + 2] = (byte) ((value >>  8) & 0xFF);
        buf[off + 3] = (byte) (value & 0xFF);

        return (Integer.SIZE / Byte.SIZE);
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

    public static final int getNextPowerOf2(int i) {
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
     * @param buffer The {@link Buffer}
     * @param lenPos The offset in the buffer where the length placeholder is
     * to be update - <B>Note:</B> assumption is that the encoded data start
     * <U>immediately</U> after the placeholder
     * @return The amount of data that has been encoded
     */
    public static int updateLengthPlaceholder(Buffer buffer, int lenPos) {
        int startPos = lenPos + (Integer.SIZE / Byte.SIZE);
        int endPos = buffer.wpos();
        int dataLength = endPos - startPos;
        buffer.wpos(lenPos);
        buffer.putInt(dataLength);
        buffer.wpos(endPos);
        return dataLength;
    }
}
