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

package org.apache.sshd.common.config.keys.loader.openssh;

import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class OpenSSHKeyPairResourceParserTestSupport extends JUnitTestSupport {
    protected static final OpenSSHKeyPairResourceParser PARSER = OpenSSHKeyPairResourceParser.INSTANCE;
    protected static final String PASSWORD = "super secret passphrase";
    protected static final FilePasswordProvider DEFAULT_PASSWORD_PROVIDER = FilePasswordProvider.of(PASSWORD);
    protected static final String ENCRYPTED_RESOURCE_PREFIX = "encrypted";

    protected BuiltinIdentities identity;

    protected void setIdentity(BuiltinIdentities identity) {
        this.identity = identity;
    }

    protected void testLoadKeyPairs(boolean encrypted, FilePasswordProvider passwordProvider) throws Exception {
        Assumptions.assumeTrue(identity.isSupported(), identity + " not supported");

        String resourceKey = identity.getName().toUpperCase() + "-" + KeyPair.class.getSimpleName();
        if (encrypted) {
            resourceKey = ENCRYPTED_RESOURCE_PREFIX + "-" + resourceKey;
        }

        URL urlKeyPair = getClass().getResource(resourceKey);
        if (encrypted) {
            Assumptions.assumeTrue(urlKeyPair != null, identity + " no encrypted test data");
            Assumptions.assumeTrue(BuiltinCiphers.aes256cbc.isSupported(),
                    BuiltinCiphers.aes256cbc.getTransformation() + " N/A");
        } else {
            assertNotNull(urlKeyPair, "Missing key-pair resource: " + resourceKey);
        }

        Collection<KeyPair> pairs;
        try {
            pairs = PARSER.loadKeyPairs(null, urlKeyPair, passwordProvider);
        } catch (Exception e) {
            e = handleResourceLoadException(resourceKey, urlKeyPair, e);
            if (e == null) {
                return;
            }

            throw e;
        }

        URL urlPubKey = getClass().getResource(resourceKey + PublicKeyEntry.PUBKEY_FILE_SUFFIX);
        assertNotNull(urlPubKey, "Missing public key resource: " + resourceKey);

        List<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(urlPubKey);
        assertEquals(1, GenericUtils.size(entries), "Mismatched public keys count");

        AuthorizedKeyEntry entry = entries.get(0);
        PublicKey pubEntry = entry.resolvePublicKey(
                null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING);
        assertNotNull(pubEntry, "Cannot retrieve public key");

        testLoadKeyPairs(encrypted, resourceKey, pairs, pubEntry);
    }

    protected Exception handleResourceLoadException(
            String resourceKey, URL urlKeyPair, Exception reason) {
        return reason;
    }

    protected abstract void testLoadKeyPairs(
            boolean encrypted, String resourceKey, Collection<KeyPair> pairs, PublicKey pubEntry)
            throws Exception;

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + identity + "]";
    }
}
