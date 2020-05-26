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
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderHolder;
import org.apache.sshd.common.config.keys.PublicKeyEntry;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultClientIdentitiesWatcher extends BuiltinClientIdentitiesWatcher {
    public DefaultClientIdentitiesWatcher(ClientIdentityLoader loader, FilePasswordProvider provider) {
        this(loader, provider, true);
    }

    public DefaultClientIdentitiesWatcher(ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(true, loader, provider, strict);
    }

    public DefaultClientIdentitiesWatcher(
                                          boolean supportedOnly, ClientIdentityLoader loader, FilePasswordProvider provider,
                                          boolean strict) {
        this(supportedOnly,
             ClientIdentityLoaderHolder.loaderHolderOf(Objects.requireNonNull(loader, "No client identity loader")),
             FilePasswordProviderHolder.providerHolderOf(Objects.requireNonNull(provider, "No password provider")),
             strict);
    }

    public DefaultClientIdentitiesWatcher(ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider) {
        this(loader, provider, true);
    }

    public DefaultClientIdentitiesWatcher(ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider,
                                          boolean strict) {
        this(true, loader, provider, strict);
    }

    public DefaultClientIdentitiesWatcher(boolean supportedOnly,
                                          ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider,
                                          boolean strict) {
        super(PublicKeyEntry.getDefaultKeysFolderPath(), supportedOnly, loader, provider, strict);
    }

    public static List<Path> getDefaultBuiltinIdentitiesPaths() {
        return getDefaultBuiltinIdentitiesPaths(PublicKeyEntry.getDefaultKeysFolderPath());
    }
}
