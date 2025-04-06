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

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
class PublicKeyEntryTest extends JUnitTestSupport {

    PublicKeyEntryTest() {
        super();
    }

    @Test
    void fallbackResolver() throws Exception {
        PublicKeyEntry entry = PublicKeyEntry.parsePublicKeyEntry(
                GenericUtils.join(
                        Arrays.asList(getCurrentTestName(), "AAAA", getClass().getSimpleName()), ' '));
        for (PublicKeyEntryResolver resolver : new PublicKeyEntryResolver[] {
                null, PublicKeyEntryResolver.FAILING, PublicKeyEntryResolver.IGNORING }) {
            try {
                PublicKey key = entry.resolvePublicKey(null, Collections.emptyMap(), resolver);
                assertSame(PublicKeyEntryResolver.IGNORING, resolver, "Mismatched successful resolver");
                assertNull(key, "Unexpected success for resolver=" + resolver + ": " + KeyUtils.getFingerPrint(key));
            } catch (GeneralSecurityException e) {
                assertObjectInstanceOf("Mismatched thrown exception for resolver=" + resolver, InvalidKeySpecException.class,
                        e);
            }
        }
    }
}
