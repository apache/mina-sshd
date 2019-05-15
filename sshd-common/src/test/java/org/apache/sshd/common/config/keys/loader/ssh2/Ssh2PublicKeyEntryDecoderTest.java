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

package org.apache.sshd.common.config.keys.loader.ssh2;

import java.io.InputStream;
import java.security.PublicKey;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.ValidateUtils;
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
public class Ssh2PublicKeyEntryDecoderTest extends JUnitTestSupport {
    public Ssh2PublicKeyEntryDecoderTest() {
        super();
    }

    @Test
    public void testMultiLineComment() throws Exception {
        testDecoder("rfc4716-multi-line-comment.ssh2");
    }

    @Test
    public void testMultipleHeaders() throws Exception {
        testDecoder("rfc4716-multiple-headers.ssh2");
    }

    private PublicKey testDecoder(String resourceName) throws Exception {
        PublicKey key;
        try (InputStream stream = ValidateUtils.checkNotNull(
                getClass().getResourceAsStream(resourceName), "Missing test resource: %s", resourceName)) {
            key = Ssh2PublicKeyEntryDecoder.INSTANCE.readPublicKey(null, () -> resourceName, stream);
        }
        assertNotNull("No key loaded from " + resourceName, key);

        String keyType = KeyUtils.getKeyType(key);
        assertNotNull("Unknown key type loaded from " + resourceName, keyType);
        return key;
    }
}
