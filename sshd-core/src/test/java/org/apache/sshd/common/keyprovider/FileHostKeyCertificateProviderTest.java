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
package org.apache.sshd.common.keyprovider;

import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FileHostKeyCertificateProviderTest extends JUnitTestSupport {

    public FileHostKeyCertificateProviderTest() {
        super();
    }

    @Test
    void loadingUserCertificateFails() {
        FileHostKeyCertificateProvider provider = new FileHostKeyCertificateProvider(
                getTestResourcesFolder().resolve("dummy_user-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX));
        Exception e = assertThrows(Exception.class, () -> provider.loadCertificates(null));
        assertTrue(e.getMessage().contains("line 1"), "Expected error in line 1");
        assertTrue(e.getMessage().contains("host") || e.getMessage().contains("user"),
                "Unexpected exception message: " + e.getMessage());
    }
}
