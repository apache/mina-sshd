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

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderHolder;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BuiltinClientIdentitiesWatcher extends ClientIdentitiesWatcher {
    private final boolean supportedOnly;

    public BuiltinClientIdentitiesWatcher(Path keysFolder, boolean supportedOnly,
                                          ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(keysFolder, NamedResource.getNameList(BuiltinIdentities.VALUES), supportedOnly, loader, provider, strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, Collection<String> ids, boolean supportedOnly,
                                          ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(keysFolder, ids, supportedOnly,
             ClientIdentityLoaderHolder.loaderHolderOf(Objects.requireNonNull(loader, "No client identity loader")),
             FilePasswordProviderHolder.providerHolderOf(Objects.requireNonNull(provider, "No password provider")),
             strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, boolean supportedOnly,
                                          ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider,
                                          boolean strict) {
        this(keysFolder, NamedResource.getNameList(BuiltinIdentities.VALUES), supportedOnly, loader, provider, strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, Collection<String> ids, boolean supportedOnly,
                                          ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider,
                                          boolean strict) {
        super(getBuiltinIdentitiesPaths(keysFolder, ids), loader, provider, strict);
        this.supportedOnly = supportedOnly;
    }

    public final boolean isSupportedOnly() {
        return supportedOnly;
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return isSupportedOnly()
                ? loadKeys(session, p -> isSupported(session, p))
                : super.loadKeys(session);
    }

    protected boolean isSupported(SessionContext session, KeyPair kp) {
        BuiltinIdentities id = BuiltinIdentities.fromKeyPair(kp);
        if ((id != null) && id.isSupported()) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("loadKeys - remove unsupported identity={}, key-type={}, key={}",
                    id, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
        }
        return false;
    }

    public static List<Path> getDefaultBuiltinIdentitiesPaths(Path keysFolder) {
        return getBuiltinIdentitiesPaths(keysFolder, NamedResource.getNameList(BuiltinIdentities.VALUES));
    }

    public static List<Path> getBuiltinIdentitiesPaths(Path keysFolder, Collection<String> ids) {
        Objects.requireNonNull(keysFolder, "No keys folder");
        if (GenericUtils.isEmpty(ids)) {
            return Collections.emptyList();
        }

        List<Path> paths = new ArrayList<>(ids.size());
        for (String id : ids) {
            String fileName = ClientIdentity.getIdentityFileName(id);
            paths.add(keysFolder.resolve(fileName));
        }

        return paths;
    }
}
