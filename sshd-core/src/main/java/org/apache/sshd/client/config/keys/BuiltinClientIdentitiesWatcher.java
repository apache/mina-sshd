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
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BuiltinClientIdentitiesWatcher extends ClientIdentitiesWatcher {
    private final boolean supportedOnly;

    public BuiltinClientIdentitiesWatcher(Path keysFolder, boolean supportedOnly,
            ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(keysFolder, NamedResource.Utils.getNameList(BuiltinIdentities.VALUES), supportedOnly, loader, provider, strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, Collection<String> ids, boolean supportedOnly,
            ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(keysFolder, ids, supportedOnly,
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(loader, "No client identity loader")),
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(provider, "No password provider")),
             strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, boolean supportedOnly,
            Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        this(keysFolder, NamedResource.Utils.getNameList(BuiltinIdentities.VALUES), supportedOnly, loader, provider, strict);
    }

    public BuiltinClientIdentitiesWatcher(Path keysFolder, Collection<String> ids, boolean supportedOnly,
            Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        super(getBuiltinIdentitiesPaths(keysFolder, ids), loader, provider, strict);
        this.supportedOnly = supportedOnly;
    }

    public final boolean isSupportedOnly() {
        return supportedOnly;
    }

    @Override
    public List<KeyPair> loadKeys() {
        List<KeyPair> keys = super.loadKeys();
        if (GenericUtils.isEmpty(keys) || (!isSupportedOnly())) {
            return keys;
        }

        Collection<KeyPair> toRemove = null;
        for (KeyPair kp : keys) {
            BuiltinIdentities id = BuiltinIdentities.fromKeyPair(kp);
            if ((id != null) && id.isSupported()) {
                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("loadKeys - remove unsupported identity={}, key-type={}, key={}",
                          id, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
            }

            if (toRemove == null) {
                toRemove = new LinkedList<>();
            }
            toRemove.add(kp);
        }

        if (GenericUtils.isEmpty(toRemove)) {
            return keys;
        }

        for (KeyPair kp : toRemove) {
            keys.remove(kp);
        }

        return keys;
    }

    public static List<Path> getDefaultBuiltinIdentitiesPaths(Path keysFolder) {
        return getBuiltinIdentitiesPaths(keysFolder, NamedResource.Utils.getNameList(BuiltinIdentities.VALUES));
    }

    public static List<Path> getBuiltinIdentitiesPaths(Path keysFolder, Collection<String> ids) {
        ValidateUtils.checkNotNull(keysFolder, "No keys folder");
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
