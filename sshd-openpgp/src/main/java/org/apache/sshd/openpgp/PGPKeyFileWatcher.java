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

import java.nio.file.LinkOption;
import java.nio.file.Path;

import org.apache.sshd.common.config.keys.loader.FileWatcherKeyPairResourceLoader;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Tracks the contents of a PGP key file - uses the default {@link PGPKeyPairResourceParser#INSTANCE instance} unless
 * otherwise specified.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPKeyFileWatcher extends FileWatcherKeyPairResourceLoader {
    public PGPKeyFileWatcher(Path file) {
        this(file, IoUtils.getLinkOptions(true));
    }

    public PGPKeyFileWatcher(Path file, LinkOption... options) {
        this(file, PGPKeyPairResourceParser.INSTANCE, options);
    }

    public PGPKeyFileWatcher(Path file, KeyPairResourceLoader delegateLoader) {
        this(file, delegateLoader, IoUtils.getLinkOptions(true));
    }

    public PGPKeyFileWatcher(Path file, KeyPairResourceLoader delegateLoader, LinkOption... options) {
        super(file, delegateLoader, options);
    }
}
