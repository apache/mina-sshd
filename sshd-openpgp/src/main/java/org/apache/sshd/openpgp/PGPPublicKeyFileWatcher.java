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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Key;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPPublicKeyFileWatcher extends ModifiableFileWatcher {
    protected final AtomicReference<Key> keyHolder = new AtomicReference<>(null);

    public PGPPublicKeyFileWatcher(Path file) {
        this(file, IoUtils.getLinkOptions(false));
    }

    public PGPPublicKeyFileWatcher(Path file, LinkOption... options) {
        super(file, options);
    }

    public Key loadPublicKey(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException, PGPException {
        Key key = keyHolder.get();
        if ((key == null) || checkReloadRequired()) {
            keyHolder.set(null); // mark as stale
            if (!exists()) {
                return null;
            }

            Path path = getPath();
            key = reloadPublicKey(session, new PathResource(path), passwordProvider);
            if (key != null) {
                if (log.isDebugEnabled()) {
                    log.debug("loadPublicKey({})[{}] loaded from {}: {}",
                            session, resourceKey, path, key);
                }
                keyHolder.set(key);
                updateReloadAttributes();
            }
        }

        return key;
    }

    protected Key reloadPublicKey(
            SessionContext session, IoResource<?> resourceKey, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException, PGPException {
        String password = (passwordProvider == null) ? null : passwordProvider.getPassword(session, resourceKey, 0);
        Key key;
        try (InputStream input = resourceKey.openInputStream()) {
            key = PGPKeyLoader.loadPGPKey(input, password);
        }

        return (key == null) ? null : key.toPublicKey();
    }
}
