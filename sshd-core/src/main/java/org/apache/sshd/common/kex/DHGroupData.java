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
package org.apache.sshd.common.kex;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Simple class holding the data for DH group key exchanges.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class DHGroupData {

    private static final ConcurrentHashMap<String, byte[]> OAKLEY_GROUPS = new ConcurrentHashMap<>();

    private DHGroupData() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static byte[] getG() {
        return new byte[] {
                (byte) 0x02
        };
    }

    public static byte[] getP1() {
        return new byte[] {
                (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
                (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
                (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
                (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
                (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
                (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
                (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
                (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
                (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
                (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
                (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
                (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
                (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
                (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53, (byte) 0x81,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
    }

    public static byte[] getP14() {
        return new byte[] {
                (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
                (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
                (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
                (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
                (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
                (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
                (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
                (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
                (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
                (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
                (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
                (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
                (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
                (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
                (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1, (byte) 0x63, (byte) 0xBF, (byte) 0x05,
                (byte) 0x98, (byte) 0xDA, (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3, (byte) 0x9A,
                (byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8, (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F,
                (byte) 0x83, (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3, (byte) 0xAD, (byte) 0x96,
                (byte) 0x1C, (byte) 0x62, (byte) 0xF3, (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB,
                (byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96, (byte) 0x96, (byte) 0x6D,
                (byte) 0x67, (byte) 0x0C, (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98, (byte) 0x04,
                (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08, (byte) 0xCA, (byte) 0x18, (byte) 0x21, (byte) 0x7C,
                (byte) 0x32, (byte) 0x90, (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36, (byte) 0xCE, (byte) 0x3B,
                (byte) 0xE3, (byte) 0x9E, (byte) 0x77, (byte) 0x2C, (byte) 0x18, (byte) 0x0E, (byte) 0x86, (byte) 0x03,
                (byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2, (byte) 0xEC, (byte) 0x07, (byte) 0xA2, (byte) 0x8F,
                (byte) 0xB5, (byte) 0xC5, (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52, (byte) 0xC9,
                (byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6, (byte) 0x95, (byte) 0x58, (byte) 0x17, (byte) 0x18,
                (byte) 0x39, (byte) 0x95, (byte) 0x49, (byte) 0x7C, (byte) 0xEA, (byte) 0x95, (byte) 0x6A, (byte) 0xE5,
                (byte) 0x15, (byte) 0xD2, (byte) 0x26, (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05, (byte) 0x10,
                (byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A, (byte) 0xAC, (byte) 0xAA, (byte) 0x68,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        };
    }

    public static byte[] getP15() {
        return getOakleyGroupPrimeValue("group15.prime");
    }

    public static byte[] getP16() {
        return getOakleyGroupPrimeValue("group16.prime");
    }

    public static byte[] getP17() {
        return getOakleyGroupPrimeValue("group17.prime");
    }

    public static byte[] getP18() {
        return getOakleyGroupPrimeValue("group18.prime");
    }

    /**
     * @param  name The name of the resource file containing the prime value data
     * @return      The prime value bytes suitable for building a {@code BigInteger}
     */
    public static byte[] getOakleyGroupPrimeValue(String name) {
        byte[] value = OAKLEY_GROUPS.computeIfAbsent(name, DHGroupData::readOakleyGroupPrimeValue);
        return (value == null) ? null : value.clone();
    }

    /**
     * Reads a HEX-encoded Oakley prime value from an internal resource file
     *
     * @param  name    The name of the resource file containing the prime value data. See
     *                 {@code org.apache.sshd.common.kex} package for available primes
     * @return         The prime value bytes suitable for building a {@code BigInteger}
     * @throws IOError If failed to access/read the required resource
     * @see            #readOakleyGroupPrimeValue(InputStream)
     */
    public static byte[] readOakleyGroupPrimeValue(String name) throws IOError {
        try (InputStream stream = DHGroupData.class.getResourceAsStream(name)) {
            if (stream == null) {
                throw new FileNotFoundException("Resource not found: " + name);
            }

            return readOakleyGroupPrimeValue(stream);
        } catch (IOException e) {
            throw new IOError(e);
        }
    }

    public static byte[] readOakleyGroupPrimeValue(InputStream stream) throws IOException {
        try (Reader rdr = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            return readOakleyGroupPrimeValue(rdr);
        }
    }

    public static byte[] readOakleyGroupPrimeValue(Reader r) throws IOException {
        try (BufferedReader br = new BufferedReader(r)) {
            return readOakleyGroupPrimeValue(br);
        }
    }

    /**
     * <P>
     * Reads a HEX encoded prime value from a possibly multi-line input as follows:
     * </P>
     * <UL>
     * <P>
     * <LI>Lines are trimmed and all whitespaces removed.</LI>
     * </P>
     *
     * <P>
     * <LI>Empty lines (after trimming) are ignored.</LI>
     * </P>
     *
     * <P>
     * <LI>Lines beginning with &quot;#&quot; are ignored (assumed to be comments).</LI>
     * </P>
     *
     * <P>
     * <LI>Remaining lines are appended to one big string assumed to contain the HEX-encoded value</LI>
     * </P>
     * </UL>
     * 
     * @param  br          The {@link BufferedReader} to read the data from
     * @return             The prime value bytes suitable for building a {@code BigInteger}
     * @throws IOException If invalid data or no encoded value found
     * @see                #parseOakleyGroupPrimeValue(String) parseOakleyGroupPrimeValue
     */
    public static byte[] readOakleyGroupPrimeValue(BufferedReader br) throws IOException {
        try {
            byte[] value = readOakleyGroupPrimeValue(br.lines());
            if (NumberUtils.isEmpty(value)) {
                throw new EOFException("No prime value data found");
            }

            return value;
        } catch (NumberFormatException e) {
            throw new StreamCorruptedException("Invalid value: " + e.getMessage());
        }
    }

    public static byte[] readOakleyGroupPrimeValue(Stream<String> lines) throws NumberFormatException {
        String str = lines
                .map(GenericUtils::trimToEmpty)
                .map(s -> s.replaceAll("\\s", ""))
                .filter(GenericUtils::isNotEmpty)
                .filter(s -> !s.startsWith("#"))
                .collect(Collectors.joining());
        return parseOakleyGroupPrimeValue(str);
    }

    /**
     * Parses the string assumed to contain a HEX-encoded Oakely prime value in big endian format
     *
     * @param  str                   The HEX-encoded string to decode - ignored if {@code null}/empty
     * @return                       The prime value bytes suitable for building a {@code BigInteger} or empty array if
     *                               no input
     * @throws NumberFormatException if malformed encoded value
     */
    public static byte[] parseOakleyGroupPrimeValue(String str) throws NumberFormatException {
        int len = GenericUtils.length(str);
        if (len <= 0) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        if ((len & 0x01) != 0) {
            throw new NumberFormatException("Incomplete HEX value representation");
        }

        byte[] group = new byte[(len / 2) + 1 /* the sign byte */];
        group[0] = 0;
        for (int l = 1, pos = 0; l < group.length; l++, pos += 2) {
            char hi = str.charAt(pos);
            char lo = str.charAt(pos + 1);
            group[l] = BufferUtils.fromHex(hi, lo);
        }

        return group;
    }
}
