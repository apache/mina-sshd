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
package org.apache.sshd.common.util.net;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SshdSocketIpv6AddressTest extends JUnitTestSupport {
    public static final List<String> VALID_ADDRESSES = Collections.unmodifiableList(
            Arrays.asList(
                    "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3:0:0:8a2e:370:7334",
                    "2001:db8:85a3::8a2e:370:7334",
                    "2001:0db8::0001", "2001:db8::1",
                    "2001:db8:0:0:0:0:2:1", "2001:db8::2:1",
                    "2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1",
                    "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                    "fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a%eth2",
                    "fe80::1ff:fe23:4567:890a%3", "fe80:3::1ff:fe23:4567:890a",
                    "::ffff:c000:0280", "::ffff:192.0.2.128"));

    private String address;
    private boolean matches;

    public void initSshdSocketIpv6AddressTest(String address, boolean matches) {
        this.address = address;
        this.matches = matches;
    }

    public static List<Object[]> parameters() {
        return Stream
                .concat(SshdSocketAddress.WELL_KNOWN_IPV6_ADDRESSES.stream(), VALID_ADDRESSES.stream())
                .map(address -> new Object[] { address, Boolean.TRUE })
                .collect(Collectors.toList());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void iPv6AddressValidity(String address, boolean matches) {
        initSshdSocketIpv6AddressTest(address, matches);
        assertEquals(address, matches, SshdSocketAddress.isIPv6Address(address));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[address=" + address
               + " , matches=" + matches
               + "]";
    }
}
