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
package org.apache.sshd.ldap;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("NoIoTestCase")
public class LdapEncodingTest extends JUnitTestSupport {

    @Test
    void testEncodeFilter() {
        assertEquals("\\00\\7F\\C3\\BF\\2A\\28\\29\\5Ca0B\\C3\\A4\\C3\\A9",
                LdapNetworkConnector.encodeFilter("\000\177\377*()\\a0Bäé"));
        assertEquals("Lu\\C4\\8Di\\C4\\87", LdapNetworkConnector.encodeFilter("Lučić")); // From RFC 4515
    }

    @Test
    void testEncodeDN() {
        assertEquals("J. Smith", LdapNetworkConnector.encodeDistinguishedName("J. Smith"));
        assertEquals("James \\\"Jim\\\" Smith", LdapNetworkConnector.encodeDistinguishedName("James \"Jim\" Smith"));
        assertEquals("Before\\0DAfter", LdapNetworkConnector.encodeDistinguishedName("Before\rAfter"));
        assertEquals("Lu\\C4\\8Di\\C4\\87", LdapNetworkConnector.encodeDistinguishedName("Lučić"));
        assertEquals("J\\C3\\B6rg M\\C3\\BCller", LdapNetworkConnector.encodeDistinguishedName("Jörg Müller"));
        assertEquals("\\#foo", LdapNetworkConnector.encodeDistinguishedName("#foo"));
        assertEquals("\\  foo \\ ", LdapNetworkConnector.encodeDistinguishedName("  foo  "));
        assertEquals("\\  foo\\00\\+\\,\\;\\<\\>\\\\bar\\ ",
                LdapNetworkConnector.encodeDistinguishedName("  foo\000+,;<>\\bar "));
    }
}
