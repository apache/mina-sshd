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

package org.apache.sshd.common.config.keys;

import java.time.Instant;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodName.class)
class OpenSshCertificateValuesTest extends JUnitTestSupport {

    OpenSshCertificateValuesTest() {
        super();
    }

    @Test
    void validAfterMinMaxSuccess() {
        OpenSshCertificateImpl cert = new OpenSshCertificateImpl();
        cert.setValidAfter(OpenSshCertificate.MIN_EPOCH);
        assertEquals(0L, cert.getValidAfter());
        cert.setValidAfter(OpenSshCertificate.INFINITY);
        assertEquals(-1L, cert.getValidAfter());
    }

    @Test
    void validBeforeMinMaxSuccess() {
        OpenSshCertificateImpl cert = new OpenSshCertificateImpl();
        cert.setValidBefore(OpenSshCertificate.MIN_EPOCH);
        assertEquals(0L, cert.getValidBefore());
        cert.setValidBefore(OpenSshCertificate.INFINITY);
        assertEquals(-1L, cert.getValidBefore());
    }

    @Test
    void validAfterOutOfBounds() {
        OpenSshCertificateImpl cert = new OpenSshCertificateImpl();
        Instant time = Instant.EPOCH.minusSeconds(1L);
        assertThrows(IllegalArgumentException.class, () -> cert.setValidAfter(time));
    }

    @Test
    void validBeforeOutOfBounds() {
        OpenSshCertificateImpl cert = new OpenSshCertificateImpl();
        Instant time = Instant.EPOCH.minusSeconds(1L);
        assertThrows(IllegalArgumentException.class, () -> cert.setValidBefore(time));
    }
}
