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
package org.apache.sshd.common.net;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Describes a range of IP addresses specified in CIDR notation.
 */
public final class InetAddressRange {

    private static final String IP4_BYTE = "(\\d{1,3})";

    private static final String IP4_DOT_BYTE = "(?:\\." + IP4_BYTE + ')';

    private static final String IP4_PREFIX = IP4_BYTE + "(?:" + IP4_DOT_BYTE + "(?:" + IP4_DOT_BYTE + "(?:" + IP4_DOT_BYTE
                                             + ")?)?)?";

    private static final String BITS = "(\\d{1,3})";

    private static final Pattern IP4_CIDR = Pattern.compile('^' + IP4_PREFIX + "/" + BITS + '$');

    private static final String IP6_WORD = "(?:[0-9a-fA-F]{1,4})";

    private static final String IP6_PART = "(" + IP6_WORD + "(?::" + IP6_WORD + ")*+)";

    private static final Pattern IP6_CIDR = Pattern.compile('^' + IP6_PART + "?(?:::" + IP6_PART + "?)?" + '/' + BITS + '$');

    private final byte[] base;

    private final byte[] mask;

    private final byte[] broadcast;

    private final int networkZoneBits;

    private InetAddressRange(byte[] base, int bits) {
        byte[] netmask = new byte[base.length];
        Builder.computeMask(netmask, bits);
        byte[] net = Builder.and(base, netmask);

        this.broadcast = Builder.invertedOr(net, netmask);
        this.base = net;
        this.mask = netmask;
        this.networkZoneBits = bits;
    }

    /**
     * Creates an {@link InetAddressRange} for a CIDR.
     *
     * @param  cidr                     the CIDR
     * @return                          an {@link InetAddressRange}
     * @throws IllegalArgumentException if the {@code cidr} cannot be parsed as a CIDR.
     */
    public static InetAddressRange fromCIDR(String cidr) {
        return Builder.build(cidr);
    }

    /**
     * Tests whether a given string is a valid CIDR.
     *
     * @param  cidr the string to test
     * @return      {@code true} if the string can be parsed as a CIDR; {@code false} otherwise
     */
    public static boolean isCIDR(String cidr) {
        try {
            return fromCIDR(cidr) != null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Tells whether this is an IPv4 address range.
     *
     * @return {@code true} if this is an IPv4 address range, {@code false} otherwise
     */
    public boolean isIpV4() {
        return base.length == 4;
    }

    /**
     * Tells whether this is an IPv6 address range.
     *
     * @return {@code true} if this is an IPv6 address range, {@code false} otherwise
     */
    public boolean isIpV6() {
        return base.length == 16;
    }

    /**
     * Retrieves the first address of this range as a MSB-first byte array.
     *
     * <p>
     * If {@code subnetBits() <= 1}, the address returned is always the zeroth address.
     * </p>
     *
     * @param  inclusive whether to consider the zeroth address the first.
     * @return           the first address of the range
     */
    public byte[] first(boolean inclusive) {
        if (inclusive || networkZoneBits + 1 >= base.length * 8) {
            return base.clone();
        }
        byte[] result = base.clone();
        result[result.length - 1] |= 1;
        return result;
    }

    /**
     * Retrieves the last address of this range as a MSB-first byte array.
     *
     * <p>
     * If {@code subnetBits() <= 1}, the address returned is always the {@link #broadcastAddress()}.
     * </p>
     *
     * @param  inclusive whether to consider the direct broadcast address the last.
     * @return           the last address of the range
     */
    public byte[] last(boolean inclusive) {
        if (inclusive || networkZoneBits + 1 >= base.length * 8) {
            return broadcast.clone();
        }
        byte[] result = broadcast.clone();
        result[result.length - 1] &= ~1;
        return result;
    }

    /**
     * Retrieves the broadcast address of this range as a MSB-first byte array.
     *
     * @return the broadcast address of the range
     */
    public byte[] broadcastAddress() {
        return broadcast.clone();
    }

    /**
     * Tests whether this range contains the given {@link InetAddress}.
     *
     * @param  address {@link InetAddress} to test
     * @return         {@code true} if the address is in the range; {@code false} otherwise
     */
    public boolean contains(InetAddress address) {
        return contains(address.getAddress());
    }

    /**
     * Tests whether this range contains the given IP address.
     *
     * @param  address the IP address to test, as an MSB-first byte array
     * @return         {@code true} if the address is in the range; {@code false} otherwise
     */
    public boolean contains(byte[] address) {
        if (address.length != mask.length) {
            return false;
        }
        return Arrays.equals(base, Builder.and(address, mask));
    }

    /**
     * Tests whether this range completely contains a given other range.
     *
     * @param  other {@link InetAddressRange} to test
     * @return       {@code true} if the other range is completely contained in this range; {@code false} otherwise
     */
    public boolean contains(InetAddressRange other) {
        return contains(other.first(true)) && contains(other.last(true));
    }

    /**
     * Tests whether this range overlaps a given other range.
     *
     * @param  other {@link InetAddressRange} to test
     * @return       {@code true} if this range overlaps with the other range; {@code false} otherwise
     */
    public boolean overlaps(InetAddressRange other) {
        return contains(other.first(true)) || contains(other.last(true));
    }

    /**
     * Retrieves the number of bits for the network zone.
     *
     * @return the number of bits for the network zone
     */
    public int networkZoneBits() {
        return networkZoneBits;
    }

    /**
     * Retrieves the number of bits for the subnet.
     *
     * @return the number of bits for the subnet
     */
    public int subnetBits() {
        return base.length * 8 - networkZoneBits;
    }

    /**
     * Determines the number of IP addresses in the range.
     *
     * <p>
     * If {@code subnetBits() <= 1}, the count always includes the first and last address.
     * </p>
     *
     * @param  inclusive whether to include the first and last (broadcast) addresses in the count
     * @return           the number of addresses in the subnet
     */
    public long numberOfAddresses(boolean inclusive) {
        long n = 1L << subnetBits();
        return (inclusive || n <= 2) ? n : n - 2;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(base);
        result = prime * result + Integer.hashCode(networkZoneBits);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        InetAddressRange other = (InetAddressRange) obj;
        return Arrays.equals(base, other.base) && networkZoneBits == other.networkZoneBits;
    }

    @Override
    public String toString() {
        if (base.length == 4) {
            return toStringIp4();
        }
        return toStringIp6();
    }

    private String toStringIp4() {
        StringBuilder b = new StringBuilder();
        int j = base.length;
        // Omit trailing zeroes
        while (j > 0 && base[j - 1] == 0) {
            j--;
        }
        for (int i = 0; i < j; i++) {
            if (i > 0) {
                b.append('.');
            }
            b.append(base[i] & 0xFF);
        }
        return b.append('/').append(networkZoneBits).toString();
    }

    private String toStringIp6() {
        StringBuilder b = new StringBuilder();
        int[] w = new int[base.length / 2];
        for (int i = 0; i < w.length; i++) {
            w[i] = ((base[2 * i] & 0xFF) << 8) + (base[2 * i + 1] & 0xFF);
        }
        // Find the longest sequence of zeroes; we'll collapse it to a single ::
        int longest = -1;
        int longestStart = -1;
        int length = -1;
        int start = -1;
        for (int i = 0; i < w.length; i++) {
            if (w[i] != 0) {
                if (length > longest) {
                    longest = length;
                    longestStart = start;
                }
                length = -1;
                start = -1;
            } else if (start < 0) {
                start = i;
                length = 1;
            } else {
                length++;
            }
        }
        if (length >= longest) {
            longest = length;
            longestStart = start;
        }
        if (longestStart < 0) {
            longestStart = w.length;
            longest = 1;
        }
        for (int i = 0; i < longestStart; i++) {
            if (i > 0) {
                b.append(':');
            }
            b.append(Integer.toHexString(w[i]));
        }
        if (longestStart < w.length) {
            b.append(':');
            if (longestStart + longest >= w.length) {
                b.append(':');
            } else {
                for (int i = longestStart + longest; i < w.length; i++) {
                    b.append(':').append(Integer.toHexString(w[i]));
                }
            }
        }
        return b.append('/').append(networkZoneBits).toString();
    }

    private static final class Builder {

        private Builder() {
            throw new IllegalStateException();
        }

        static InetAddressRange build(String cidr) {
            IllegalArgumentException ex = null;
            if (!cidr.isEmpty()) {
                try {
                    if ("/0".equals(cidr)) {
                        return new InetAddressRange(new byte[4], 0);
                    }
                    Matcher m = IP4_CIDR.matcher(cidr);
                    if (m.matches()) {
                        return fromIp4(m);
                    }
                    m = IP6_CIDR.matcher(cidr);
                    if (m.matches() && cidr.charAt(0) != '/') {
                        return fromIp6(m);
                    }
                } catch (IllegalArgumentException e) {
                    ex = e;
                }
            }
            throw new IllegalArgumentException(cidr + " is not a CIDR", ex);
        }

        private static InetAddressRange fromIp4(Matcher m) {
            byte[] base = new byte[4];
            for (int i = 0; i < 4; i++) {
                String s = m.group(i + 1);
                if (s != null && !s.isEmpty()) {
                    base[i] = byteRange(Integer.parseInt(s));
                }
            }
            int bits = Integer.parseInt(m.group(5));
            return new InetAddressRange(base, bits);
        }

        private static InetAddressRange fromIp6(Matcher m) {
            String prefix = m.group(1);
            String suffix = m.group(2);
            String[] pre = prefix == null ? new String[0] : prefix.split(":");
            String[] post = suffix == null ? new String[0] : suffix.split(":");
            if (pre.length + post.length > 8) {
                throw new IllegalArgumentException("Too many components");
            }
            byte[] base = new byte[16];
            for (int i = 0; i < pre.length; i++) {
                int w = wordRange(Integer.parseInt(pre[i], 16));
                base[2 * i] = (byte) (w >>> 8);
                base[2 * i + 1] = (byte) w;
            }
            for (int i = post.length - 1, j = base.length / 2 - 1; i >= 0; i--, j--) {
                int w = wordRange(Integer.parseInt(post[i], 16));
                base[2 * j] = (byte) (w >>> 8);
                base[2 * j + 1] = (byte) w;
            }
            int bits = Integer.parseInt(m.group(3));
            return new InetAddressRange(base, bits);
        }

        private static byte byteRange(int x) {
            rangeCheck(x, 0, 255);
            return (byte) x;
        }

        private static int wordRange(int x) {
            rangeCheck(x, 0, 1 << 16 - 1);
            return x;
        }

        private static void rangeCheck(int x, int min, int max) {
            if (x < min || x > max) {
                throw new IllegalArgumentException(x + " not in range [" + min + ',' + max + ']');
            }
        }

        static void computeMask(byte[] mask, int bits) {
            rangeCheck(bits, 0, mask.length * 8);
            for (int i = 0; i < bits; i++) {
                int j = i / 8;
                int b = 1 << 7 - (i % 8);
                mask[j] |= b;
            }
        }

        static byte[] and(byte[] a, byte[] b) {
            if (a.length != b.length) {
                throw new IllegalArgumentException();
            }
            byte[] r = a.clone();
            for (int i = 0; i < a.length; i++) {
                r[i] &= b[i];
            }
            return r;
        }

        static byte[] invertedOr(byte[] a, byte[] b) {
            if (a.length != b.length) {
                throw new IllegalArgumentException();
            }
            byte[] r = a.clone();
            for (int i = 0; i < a.length; i++) {
                r[i] |= ~b[i];
            }
            return r;
        }
    }
}
