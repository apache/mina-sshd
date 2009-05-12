/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.keyprovider;

import java.io.File;

import org.junit.Test;
import org.apache.sshd.common.KeyPairProvider;

import static org.junit.Assert.*;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleGeneratorHostKeyProviderTest {

    @Test
    public void testDSA() {
        File path = new File("target/keys");
        path.mkdirs();
        path = new File(path, "simple.key");
        path.delete();

        // Generate
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("DSA");
        provider.setKeySize(512);
        provider.setPath(path.getPath());
        assertEquals(KeyPairProvider.SSH_DSS, provider.getKeyTypes());
        assertNotNull(provider.loadKey(KeyPairProvider.SSH_DSS));

        // Read existing
        provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("DSA");
        provider.setKeySize(512);
        provider.setPath(path.getPath());
        assertEquals(KeyPairProvider.SSH_DSS, provider.getKeyTypes());
        assertNotNull(provider.loadKey(KeyPairProvider.SSH_DSS));
    }

    @Test
    public void testRSA() {
        File path = new File("target/keys");
        path.mkdirs();
        path = new File(path, "simple.key");
        path.delete();

        // Generate
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("RSA");
        provider.setKeySize(32);
        provider.setPath(path.getPath());
        assertEquals(KeyPairProvider.SSH_RSA, provider.getKeyTypes());
        assertNotNull(provider.loadKey(KeyPairProvider.SSH_RSA));

        // Read existing
        provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("RSA");
        provider.setKeySize(32);
        provider.setPath(path.getPath());
        assertEquals(KeyPairProvider.SSH_RSA, provider.getKeyTypes());
        assertNotNull(provider.loadKey(KeyPairProvider.SSH_RSA));
    }
}
