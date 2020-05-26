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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PublicKeyEntryTest extends JUnitTestSupport {
    public PublicKeyEntryTest() {
        super();
    }

    @Test
    public void testFallbackResolver() throws Exception {
        PublicKeyEntry entry = PublicKeyEntry.parsePublicKeyEntry(
                GenericUtils.join(
                        Arrays.asList(getCurrentTestName(), "AAAA", getClass().getSimpleName()), ' '));
        for (PublicKeyEntryResolver resolver : new PublicKeyEntryResolver[] {
                null, PublicKeyEntryResolver.FAILING, PublicKeyEntryResolver.IGNORING }) {
            try {
                PublicKey key = entry.resolvePublicKey(null, Collections.emptyMap(), resolver);
                assertSame("Mismatched successful resolver", PublicKeyEntryResolver.IGNORING, resolver);
                assertNull("Unexpected success for resolver=" + resolver + ": " + KeyUtils.getFingerPrint(key), key);
            } catch (GeneralSecurityException e) {
                assertObjectInstanceOf("Mismatched thrown exception for resolver=" + resolver, InvalidKeySpecException.class,
                        e);
            }
        }
    }
}
