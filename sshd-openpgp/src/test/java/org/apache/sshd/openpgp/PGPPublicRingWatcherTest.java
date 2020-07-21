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

package org.apache.sshd.openpgp;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;
import java.util.NavigableMap;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PGPPublicRingWatcherTest extends JUnitTestSupport {
    public PGPPublicRingWatcherTest() {
        super();
    }

    @Test
    public void testDefaultRingPath() {
        Path path = PGPPublicRingWatcher.detectDefaultPublicRingFilePath();
        Assume.assumeTrue("No default ring detected", path != null);

        try {
            testPublicRingWatcher(path);
        } catch (Exception e) {
            outputDebugMessage("Failed (%s) to load keys from ring=%s: %s",
                    e.getClass().getSimpleName(), path, e.getMessage());
        }
    }

    @Test
    public void testV1ResourcesKeyPath() throws Exception {
        Path dir = CommonTestSupportUtils.resolve(
                detectSourcesFolder(), TEST_SUBFOLDER, RESOURCES_SUBFOLDER, "keyring");
        Path file = dir.resolve(PGPPublicRingWatcher.GPG_V1_PUBLIC_RING_FILENAME);
        Map<String, PublicKey> keys = testPublicRingWatcher(file);
        assertFalse("No keys extracted", GenericUtils.isEmpty(keys));
    }

    @Test
    public void testV2ResourcesKeyPath() throws Exception {
        Path dir = CommonTestSupportUtils.resolve(
                detectSourcesFolder(), TEST_SUBFOLDER, RESOURCES_SUBFOLDER, "kbx2ring");
        Path file = dir.resolve(PGPPublicRingWatcher.GPG_V2_PUBLIC_RING_FILENAME);
        Map<String, PublicKey> keys = testPublicRingWatcher(file);
        assertFalse("No keys extracted", GenericUtils.isEmpty(keys));
    }

    private NavigableMap<String, PublicKey> testPublicRingWatcher(Path file) throws Exception {
        PGPPublicRingWatcher watcher = new PGPPublicRingWatcher(file);
        NavigableMap<String, PublicKey> keys = watcher.reloadRingKeys(null, new PathResource(file));
        int numKeys = GenericUtils.size(keys);
        outputDebugMessage("%s: Loaded %d keys from %s", getCurrentTestName(), numKeys, file);

        if (numKeys > 0) {
            for (Map.Entry<String, PublicKey> ke : keys.entrySet()) {
                String fp = ke.getKey();
                PublicKey k = ke.getValue();
                outputDebugMessage("%s: %s %s[%d] %s",
                        getCurrentTestName(), fp, KeyUtils.getKeyType(k),
                        KeyUtils.getKeySize(k), KeyUtils.getFingerPrint(k));
            }
        }

        return keys;
    }
}
