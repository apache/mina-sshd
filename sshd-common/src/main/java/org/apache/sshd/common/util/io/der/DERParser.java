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

package org.apache.sshd.common.util.io.der;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.util.Arrays;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * A bare minimum DER parser - just enough to be able to decode signatures and private keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DERParser extends FilterInputStream {
    /**
     * Maximum size of data allowed by {@link #readLength()} - it is a bit arbitrary since one can encode 32-bit length
     * data, but it is good enough for the keys
     */
    public static final int MAX_DER_VALUE_LENGTH = 2 * Short.MAX_VALUE;

    private final byte[] lenBytes = new byte[Integer.BYTES];

    public DERParser(byte... bytes) {
        this(bytes, 0, NumberUtils.length(bytes));
    }

    public DERParser(byte[] bytes, int offset, int len) {
        this(new ByteArrayInputStream(bytes, offset, len));
    }

    public DERParser(InputStream s) {
        super(s);
    }

    /**
     * Decode the length of the field. Can only support length encoding up to 4 octets. In BER/DER encoding, length can
     * be encoded in 2 forms:
     * <ul>
     * <li>
     * <p>
     * Short form - One octet. Bit 8 has value "0" and bits 7-1 give the length.
     * </p>
     * </li>
     *
     * <li>
     * <p>
     * Long form - Two to 127 octets (only 4 is supported here). Bit 8 of first octet has value "1" and bits 7-1 give
     * the number of additional length octets. Second and following octets give the length, base 256, most significant
     * digit first.
     * </p>
     * </li>
     * </ul>
     *
     * @return             The length as integer
     * @throws IOException If invalid format found
     */
    public int readLength() throws IOException {
        int i = read();
        if (i == -1) {
            throw new StreamCorruptedException("Invalid DER: length missing");
        }

        // A single byte short length
        if ((i & ~0x7F) == 0) {
            return i;
        }

        int num = i & 0x7F;
        // TODO We can't handle length longer than 4 bytes
        if ((i >= 0xFF) || (num > lenBytes.length)) {
            throw new StreamCorruptedException("Invalid DER: length field too big: " + i);
        }

        // place the read bytes last so that the 1st ones are zeroes as big endian
        Arrays.fill(lenBytes, (byte) 0);
        int n = read(lenBytes, 4 - num, num);
        if (n < num) {
            throw new StreamCorruptedException("Invalid DER: length data too short: expected=" + num + ", actual=" + n);
        }

        long len = BufferUtils.getUInt(lenBytes);
        if (len < 0x7FL) { // according to standard: "the shortest possible length encoding must be used"
            throw new StreamCorruptedException("Invalid DER: length not in shortest form: " + len);
        }

        if (len > MAX_DER_VALUE_LENGTH) {
            throw new StreamCorruptedException(
                    "Invalid DER: data length too big: " + len + " (max=" + MAX_DER_VALUE_LENGTH + ")");
        }

        // we know the cast is safe since it is less than MAX_DER_VALUE_LENGTH which is ~64K
        return (int) len;
    }

    public ASN1Object readObject() throws IOException {
        int tag = read();
        if (tag == -1) {
            return null;
        }

        ASN1Type objType = ASN1Type.fromDERValue(tag);
        if (objType == ASN1Type.NULL) {
            return new ASN1Object((byte) tag, 0, GenericUtils.EMPTY_BYTE_ARRAY);
        }

        int length = readLength();
        byte[] value = new byte[length];
        int n = read(value);
        if (n < length) {
            throw new StreamCorruptedException(
                    "Invalid DER: stream too short, missing value: read " + n + " out of required " + length);
        }

        return new ASN1Object((byte) tag, length, value);
    }

    public BigInteger readBigInteger() throws IOException {
        int type = read();
        if (type != 0x02) {
            throw new StreamCorruptedException("Invalid DER: data type is not an INTEGER: 0x" + Integer.toHexString(type));
        }

        int len = readLength();
        byte[] value = new byte[len];
        int n = read(value);
        if (n < len) {
            throw new StreamCorruptedException(
                    "Invalid DER: stream too short, missing value: read " + n + " out of required " + len);
        }

        return new BigInteger(value);
    }
}
