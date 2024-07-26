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

import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertThrows;

@TestMethodOrder(MethodName.class)
public class OpenSshCertificateValuesTest {

    public OpenSshCertificateValuesTest() {
        super();
    }

    @Test
    void validAfterMinMaxSuccess() {
        new OpenSshCertificateImpl().setValidAfter(OpenSshCertificate.MIN_EPOCH);
        new OpenSshCertificateImpl().setValidAfter(OpenSshCertificate.INFINITY);
    }

    @Test
    void validBeforeMinMaxSuccess() {
        new OpenSshCertificateImpl().setValidBefore(OpenSshCertificate.MIN_EPOCH);
        new OpenSshCertificateImpl().setValidBefore(OpenSshCertificate.INFINITY);
    }

    @Test
    void validAfterOutOfBounds() {
        assertThrows(IllegalArgumentException.class, () -> {
            new OpenSshCertificateImpl().setValidAfter(Instant.EPOCH.minusSeconds(1L));
        });
    }

    @Test
    void validBeforeOutOfBounds() {
        assertThrows(IllegalArgumentException.class, () -> {
            new OpenSshCertificateImpl().setValidBefore(Instant.EPOCH.minusSeconds(1L));
        });
    }
}
