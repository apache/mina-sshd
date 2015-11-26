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

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.ValidateUtils;

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

    public DefaultClientIdentitiesWatcher(boolean supportedOnly, ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(supportedOnly,
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(loader, "No client identity loader")),
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(provider, "No password provider")),
             strict);
    }

    public DefaultClientIdentitiesWatcher(Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider) {
        this(loader, provider, true);
    }

    public DefaultClientIdentitiesWatcher(Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        this(true, loader, provider, strict);
    }

    public DefaultClientIdentitiesWatcher(boolean supportedOnly,
            Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        super(PublicKeyEntry.getDefaultKeysFolderPath(), supportedOnly, loader, provider, strict);
    }

    public static List<Path> getDefaultBuiltinIdentitiesPaths() {
        return getDefaultBuiltinIdentitiesPaths(PublicKeyEntry.getDefaultKeysFolderPath());
    }
}
