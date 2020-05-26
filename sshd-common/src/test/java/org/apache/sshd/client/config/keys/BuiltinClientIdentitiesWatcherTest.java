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

package org.apache.sshd.client.config.keys;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
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
public class BuiltinClientIdentitiesWatcherTest extends JUnitTestSupport {
    public BuiltinClientIdentitiesWatcherTest() {
        super();
    }

    @Test
    public void testMultipleFilesWatch() throws Exception {
        KeyPair identity = CommonTestSupportUtils.getFirstKeyPair(createTestHostKeyProvider());
        String keyType
                = ValidateUtils.checkNotNullAndNotEmpty(KeyUtils.getKeyType(identity), "Cannot determine identity key type");

        Path dir = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        Map<BuiltinIdentities, Path> locationsMap = new EnumMap<>(BuiltinIdentities.class);
        Map<BuiltinIdentities, KeyPair> idsMap = new EnumMap<>(BuiltinIdentities.class);
        for (BuiltinIdentities id : BuiltinIdentities.VALUES) {
            Path idFile = dir.resolve(ClientIdentity.getIdentityFileName(id));
            Files.deleteIfExists(idFile);
            assertNull("Multiple file mappings for " + id, locationsMap.put(id, idFile));
            assertNull("Multiple identity mappings for " + id, idsMap.put(id, KeyUtils.cloneKeyPair(keyType, identity)));
        }

        ClientIdentityLoader loader = new ClientIdentityLoader() {
            @Override
            public Iterable<KeyPair> loadClientIdentities(
                    SessionContext session, NamedResource location, FilePasswordProvider provider)
                    throws IOException, GeneralSecurityException {
                BuiltinIdentities id = findIdentity(location);
                assertNotNull("Invalid location: " + location, id);
                KeyPair kp = idsMap.get(id);
                return (kp == null) ? null : Collections.singletonList(kp);
            }

            @Override
            public boolean isValidLocation(NamedResource location) throws IOException {
                return findIdentity(location) != null;
            }

            private BuiltinIdentities findIdentity(NamedResource location) {
                String idPath = (location == null) ? null : location.getName();
                if (GenericUtils.isEmpty(idPath)) {
                    return null;
                }

                for (Map.Entry<BuiltinIdentities, Path> le : locationsMap.entrySet()) {
                    Path path = le.getValue();
                    if (String.CASE_INSENSITIVE_ORDER.compare(idPath, path.toString()) == 0) {
                        return le.getKey();
                    }
                }

                return null;
            }
        };

        Map<BuiltinIdentities, KeyPair> existing = new EnumMap<>(BuiltinIdentities.class);
        KeyPairProvider watcher = new BuiltinClientIdentitiesWatcher(dir, false, loader, FilePasswordProvider.EMPTY, false);
        testMultipleFilesWatch("No files", watcher, existing.values());

        for (BuiltinIdentities id : BuiltinIdentities.VALUES) {
            String phase = id + " + " + Objects.toString(existing.keySet());
            touchIdentityFile(locationsMap.get(id));
            existing.put(id, idsMap.get(id));

            for (int index = 0; index < Byte.SIZE; index++) {
                testMultipleFilesWatch(phase + "[" + index + "]", watcher, existing.values());
            }
        }

        testMultipleFilesWatch("All files", watcher, existing.values());

        for (BuiltinIdentities id : BuiltinIdentities.VALUES) {
            existing.remove(id);
            Files.deleteIfExists(locationsMap.get(id));
            String phase = Objects.toString(existing.keySet()) + " - " + id;

            for (int index = 0; index < Byte.SIZE; index++) {
                testMultipleFilesWatch(phase + "[" + index + "]", watcher, existing.values());
            }
        }
    }

    private static void touchIdentityFile(Path idFile) throws IOException {
        OpenOption[] options = IoUtils.EMPTY_OPEN_OPTIONS;
        if (Files.exists(idFile, IoUtils.EMPTY_LINK_OPTIONS)) {
            options = new OpenOption[] { StandardOpenOption.WRITE, StandardOpenOption.APPEND };
        }

        try (OutputStream out = Files.newOutputStream(idFile, options)) {
            out.write(new Date(System.currentTimeMillis()).toString().getBytes(StandardCharsets.UTF_8));
            out.write('\n');
        }
    }

    private static void testMultipleFilesWatch(
            String phase, KeyIdentityProvider watcher, Collection<? extends KeyPair> expected)
            throws IOException, GeneralSecurityException {
        Iterable<KeyPair> keys = watcher.loadKeys(null);
        Collection<KeyPair> actual = new ArrayList<>();
        for (KeyPair kp : keys) {
            actual.add(kp);
        }
        assertEquals(phase + ": mismatched sizes", GenericUtils.size(expected), GenericUtils.size(actual));

        if (!GenericUtils.isEmpty(expected)) {
            for (KeyPair kp : expected) {
                assertTrue(phase + ": missing key", actual.contains(kp));
            }
        }
    }
}
