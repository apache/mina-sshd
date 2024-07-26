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
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class PGPPublicRingWatcherTest extends JUnitTestSupport {
    public PGPPublicRingWatcherTest() {
        super();
    }

    @Test
    void defaultRingPath() {
        Path path = PGPPublicRingWatcher.detectDefaultPublicRingFilePath();
        Assumptions.assumeTrue(path != null, "No default ring detected");

        try {
            testPublicRingWatcher(path);
        } catch (Exception e) {
            outputDebugMessage("Failed (%s) to load keys from ring=%s: %s",
                    e.getClass().getSimpleName(), path, e.getMessage());
        }
    }

    @Test
    void v1ResourcesKeyPath() throws Exception {
        Path dir = CommonTestSupportUtils.resolve(
                detectSourcesFolder(), TEST_SUBFOLDER, RESOURCES_SUBFOLDER, "keyring");
        Path file = dir.resolve(PGPPublicRingWatcher.GPG_V1_PUBLIC_RING_FILENAME);
        Map<String, PublicKey> keys = testPublicRingWatcher(file);
        assertFalse(MapEntryUtils.isEmpty(keys), "No keys extracted");
    }

    @Test
    void v2ResourcesKeyPath() throws Exception {
        Path dir = CommonTestSupportUtils.resolve(
                detectSourcesFolder(), TEST_SUBFOLDER, RESOURCES_SUBFOLDER, "kbx2ring");
        Path file = dir.resolve(PGPPublicRingWatcher.GPG_V2_PUBLIC_RING_FILENAME);
        Map<String, PublicKey> keys = testPublicRingWatcher(file);
        assertFalse(MapEntryUtils.isEmpty(keys), "No keys extracted");
    }

    private NavigableMap<String, PublicKey> testPublicRingWatcher(Path file) throws Exception {
        PGPPublicRingWatcher watcher = new PGPPublicRingWatcher(file);
        NavigableMap<String, PublicKey> keys = watcher.reloadRingKeys(null, new PathResource(file));
        int numKeys = MapEntryUtils.size(keys);
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
