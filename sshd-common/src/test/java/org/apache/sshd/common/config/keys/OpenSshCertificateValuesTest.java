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

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OpenSshCertificateValuesTest {

    public OpenSshCertificateValuesTest() {
        super();
    }

    @Test
    public void testValidAfterMinMaxSuccess() {
        new OpenSshCertificateImpl().setValidAfter(OpenSshCertificate.MIN_EPOCH);
        new OpenSshCertificateImpl().setValidAfter(OpenSshCertificate.INFINITY);
    }

    @Test
    public void testValidBeforeMinMaxSuccess() {
        new OpenSshCertificateImpl().setValidBefore(OpenSshCertificate.MIN_EPOCH);
        new OpenSshCertificateImpl().setValidBefore(OpenSshCertificate.INFINITY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidAfterOutOfBounds() {
        new OpenSshCertificateImpl().setValidAfter(Instant.EPOCH.minusSeconds(1L));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidBeforeOutOfBounds() {
        new OpenSshCertificateImpl().setValidBefore(Instant.EPOCH.minusSeconds(1L));
    }
}
