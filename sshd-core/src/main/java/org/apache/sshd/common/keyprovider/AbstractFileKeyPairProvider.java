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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * This host key provider loads private keys from the specified files. The
 * loading is <U>lazy</U> - i.e., a file is not loaded until it is actually
 * required. Once required though, its loaded {@link KeyPair} result is
 * <U>cached</U> and not re-loaded.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFileKeyPairProvider extends AbstractResourceKeyPairProvider<Path> {
    private Collection<? extends Path> files;

    protected AbstractFileKeyPairProvider() {
        super();
    }

    public Collection<? extends Path> getPaths() {
        return files;
    }

    public void setFiles(Collection<File> files) {
        if (GenericUtils.isEmpty(files)) {
            setPaths(Collections.<Path>emptyList());
        } else {
            List<Path> paths = new ArrayList<>(files.size());
            for (File f : files) {
                paths.add(f.toPath());
            }
            setPaths(paths);
        }
    }

    public void setPaths(Collection<? extends Path> paths) {
        int numPaths = GenericUtils.size(paths);
        Collection<Path> resolved = (numPaths <= 0) ? Collections.<Path>emptyList() : new ArrayList<Path>(paths.size());
        // use absolute path in order to have unique cache keys
        if (numPaths > 0) {
            for (Path p : paths) {
                resolved.add(p.toAbsolutePath());
            }
        }

        resetCacheMap(resolved);
        files = resolved;
    }

    @Override
    public Iterable<KeyPair> loadKeys() {
        return loadKeys(getPaths());
    }

    @Override
    protected KeyPair doLoadKey(Path resource) throws IOException, GeneralSecurityException {
        return super.doLoadKey((resource == null) ? null : resource.toAbsolutePath());
    }

    @Override
    protected InputStream openKeyPairResource(String resourceKey, Path resource) throws IOException {
        return Files.newInputStream(resource, IoUtils.EMPTY_OPEN_OPTIONS);
    }
}
