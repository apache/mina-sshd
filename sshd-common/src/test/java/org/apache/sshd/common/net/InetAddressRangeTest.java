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
import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("NoIoTestCase")
class InetAddressRangeTest extends JUnitTestSupport {

    static Stream<Arguments> ip4Cidrs() {
        return Stream.of(
                Arguments.of("192.168.17.17/16", "192.168/16"),
                Arguments.of("10.0.2.5/24", "10.0.2/24"),
                Arguments.of("192.168.17.43/32", "192.168.17.43/32"),
                Arguments.of("192.168.17.43/0", "/0"));
    }

    @ParameterizedTest(name = "{0} - {1}")
    @MethodSource("ip4Cidrs")
    void toStringIp4(String cidr, String expected) {
        InetAddressRange range = InetAddressRange.fromCIDR(cidr);
        assertTrue(range.isIpV4());
        assertFalse(range.isIpV6());
        String str = range.toString();
        assertEquals(range, InetAddressRange.fromCIDR(str));
        assertEquals(expected, str);
    }

    static Stream<Arguments> ip6Cidrs() {
        return Stream.of(
                Arguments.of("2001:0df8:23f2:0000:0000:66ee:1336:1774/96", "2001:df8:23f2:0:0:66ee::/96"),
                Arguments.of("2001:0df8:0000:0000:0000:66ee:1336:1774/96", "2001:df8::66ee:0:0/96"),
                Arguments.of("2001:df8::/32", "2001:df8::/32"),
                Arguments.of("0:0::/66", "::/66"));
    }

    @ParameterizedTest(name = "{0} - {1}")
    @MethodSource("ip6Cidrs")
    void toStringIp6(String cidr, String expected) {
        InetAddressRange range = InetAddressRange.fromCIDR(cidr);
        assertTrue(range.isIpV6());
        assertFalse(range.isIpV4());
        String str = range.toString();
        assertEquals(range, InetAddressRange.fromCIDR(str));
        assertEquals(expected, str);
    }

    static Stream<Arguments> ip4Contains() {
        return Stream.of(
                Arguments.of("192.168.17.17/24", "192.168.17/24", 256, "192.168.17.0", "192.168.17.255"),
                Arguments.of("10.0.5.5/22", "10.0.4/22", 1024, "10.0.4.0", "10.0.7.255"));
    }

    @ParameterizedTest(name = "{0} - {1}")
    @MethodSource("ip4Contains")
    void containsIp4(String cidr, String expected, int size, String first, String last) throws Exception {
        InetAddressRange range = InetAddressRange.fromCIDR(cidr);
        assertTrue(range.isIpV4());
        assertEquals(size, range.numberOfAddresses(true));
        assertEquals(size - 2, range.numberOfAddresses(false));
        byte[] from = range.first(true);
        byte[] to = range.last(true);
        assertArrayEquals(InetAddress.getByName(first).getAddress(), from);
        assertArrayEquals(InetAddress.getByName(last).getAddress(), to);
        int n = 0;
        while (!Arrays.equals(from, to)) {
            assertTrue(range.contains(from));
            n++;
            inc(from);
        }
        assertTrue(range.contains(from));
        n++;
        assertEquals(size, n);
        inc(from);
        assertFalse(range.contains(from));
        String str = range.toString();
        assertEquals(range, InetAddressRange.fromCIDR(str));
        assertEquals(expected, str);
    }

    private void inc(byte[] b) {
        for (int i = b.length - 1; i >= 0; i--) {
            int x = (b[i] & 0xFF) + 1;
            b[i] = (byte) x;
            if (x < 256) {
                break;
            }
        }
    }

    static Stream<Arguments> ip4Bounds() {
        return Stream.of(Arguments.of("192.168.17.17/30", 30, 2, 4, "192.168.17.16", "192.168.17.19"),
                Arguments.of("192.168.17.17/31", 31, 1, 2, "192.168.17.16", "192.168.17.17"),
                Arguments.of("192.168.17.17/32", 32, 0, 1, "192.168.17.17", "192.168.17.17"));
    }

    @ParameterizedTest(name = "{0} - {1}")
    @MethodSource("ip4Bounds")
    void boundsIp4(String cidr, int net, int subnet, int size, String first, String last) throws Exception {
        InetAddressRange range = InetAddressRange.fromCIDR(cidr);
        assertTrue(range.isIpV4());
        assertEquals(net, range.networkZoneBits());
        assertEquals(subnet, range.subnetBits());
        assertEquals(size, range.numberOfAddresses(true));
        if (size <= 2) {
            assertEquals(size, range.numberOfAddresses(false));
        } else {
            assertEquals(size - 2, range.numberOfAddresses(false));
        }
        byte[] from = range.first(true);
        byte[] to = range.last(true);
        assertArrayEquals(InetAddress.getByName(first).getAddress(), from);
        assertArrayEquals(InetAddress.getByName(last).getAddress(), to);
    }

    @Test
    void leadingZeroesIp6() {
        InetAddressRange range = InetAddressRange.fromCIDR("0000:0000:0000:1234:5678:1234:5678::/96");
        String str = range.toString();
        assertEquals("::1234:5678:1234:0:0/96", str);
        assertEquals(range, InetAddressRange.fromCIDR(str));
    }
}
