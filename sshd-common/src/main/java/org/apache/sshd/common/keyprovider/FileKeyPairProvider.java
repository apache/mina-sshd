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
package org.apache.sshd.common.keyprovider;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;

/**
 * This host key provider loads private keys from the specified files. The loading is <U>lazy</U> - i.e., a file is not
 * loaded until it is actually required. Once required though, its loaded {@link KeyPair} result is <U>cached</U> and
 * not re-loaded.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileKeyPairProvider extends AbstractResourceKeyPairProvider<Path> {
    private Collection<? extends Path> files;

    public FileKeyPairProvider() {
        super();
    }

    public FileKeyPairProvider(Path path) {
        this(Collections.singletonList(Objects.requireNonNull(path, "No path provided")));
    }

    public FileKeyPairProvider(Path... files) {
        this(Arrays.asList(files));
    }

    public FileKeyPairProvider(Collection<? extends Path> files) {
        this.files = files;
    }

    public Collection<? extends Path> getPaths() {
        return files;
    }

    public void setPaths(Collection<? extends Path> paths) {
        // use absolute path in order to have unique cache keys
        Collection<Path> resolved = GenericUtils.map(paths, Path::toAbsolutePath);
        resetCacheMap(resolved);
        files = resolved;
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return loadKeys(session, getPaths());
    }

    @Override
    protected IoResource<Path> getIoResource(SessionContext session, Path resource) {
        return (resource == null) ? null : new PathResource(resource);
    }

    @Override
    protected Iterable<KeyPair> doLoadKeys(SessionContext session, Path resource)
            throws IOException, GeneralSecurityException {
        return super.doLoadKeys(session, (resource == null) ? null : resource.toAbsolutePath());
    }
}
