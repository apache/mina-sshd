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

package org.apache.sshd.common.config.keys.loader;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.common.util.io.resource.PathResource;

/**
 * Tracks a file containing {@link KeyPair}-s an re-loads it whenever a change has been sensed in the monitored file (if
 * it exists)
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileWatcherKeyPairResourceLoader extends ModifiableFileWatcher implements KeyPairResourceLoader {
    protected final AtomicReference<Collection<KeyPair>> keysHolder = new AtomicReference<>(Collections.emptyList());
    private KeyPairResourceLoader delegateLoader;

    public FileWatcherKeyPairResourceLoader(Path file, KeyPairResourceLoader delegateLoader) {
        this(file, delegateLoader, IoUtils.getLinkOptions(true));
    }

    public FileWatcherKeyPairResourceLoader(
                                            Path file, KeyPairResourceLoader delegateLoader, LinkOption... options) {
        super(file, options);
        this.delegateLoader = Objects.requireNonNull(delegateLoader, "No delegate loader provided");
    }

    public KeyPairResourceLoader getKeyPairResourceLoader() {
        return delegateLoader;
    }

    public void setKeyPairResourceLoader(KeyPairResourceLoader loader) {
        this.delegateLoader = Objects.requireNonNull(loader, "No delegate loader provided");
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey,
            FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException {

        Collection<KeyPair> ids = keysHolder.get();
        if (GenericUtils.isEmpty(ids) || checkReloadRequired()) {
            keysHolder.set(Collections.emptyList()); // mark stale

            if (!exists()) {
                return keysHolder.get();
            }

            Path path = getPath();
            ids = reloadKeyPairs(session, new PathResource(path), passwordProvider, lines);
            int numKeys = GenericUtils.size(ids);
            if (log.isDebugEnabled()) {
                log.debug("loadKeyPairs({})[{}] reloaded {} keys from {}",
                        session, resourceKey, numKeys, path);
            }

            if (numKeys > 0) {
                keysHolder.set(ids);
                updateReloadAttributes();
            }
        }

        return ids;
    }

    protected Collection<KeyPair> reloadKeyPairs(
            SessionContext session, NamedResource resourceKey,
            FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException {
        KeyPairResourceLoader loader
                = ValidateUtils.checkNotNull(getKeyPairResourceLoader(), "No resource loader for %s", resourceKey.getName());
        return loader.loadKeyPairs(session, resourceKey, passwordProvider, lines);
    }
}
