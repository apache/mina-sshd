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

package org.apache.sshd.scp.common.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.ScpModuleProperties;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpSourceStreamResolver;
import org.apache.sshd.scp.common.ScpTargetStreamResolver;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpFileOpener extends AbstractLoggingBean implements ScpFileOpener {
    public static final DefaultScpFileOpener INSTANCE = new DefaultScpFileOpener();

    private static final OpenOption[] DEFAULT_SYNC_OPTIONS = {
            StandardOpenOption.SYNC, StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE
    };

    public DefaultScpFileOpener() {
        super();
    }

    @Override
    public InputStream openRead(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("openRead({}) size={}, permissions={}, file={}, options={}",
                    session, size, permissions, file, Arrays.toString(options));
        }

        return Files.newInputStream(file, options);
    }

    @Override
    public OutputStream openWrite(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException {
        options = resolveOpenOptions(session, file, size, permissions, options);
        if (log.isDebugEnabled()) {
            log.debug("openWrite({}) size={}, permissions={}, file={}, options={}",
                    session, size, permissions, file, Arrays.toString(options));
        }
        return Files.newOutputStream(file, options);
    }

    protected OpenOption[] resolveOpenOptions(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException {
        if (!ScpModuleProperties.PROP_AUTO_SYNC_FILE_ON_WRITE.getRequired(session)) {
            return options;
        }

        int numOptions = GenericUtils.length(options);
        if (numOptions <= 0) {
            return DEFAULT_SYNC_OPTIONS.clone();
        }

        OpenOption syncOption = Stream.of(options)
                .filter(o -> o == StandardOpenOption.SYNC)
                .findFirst()
                .orElse(null);
        if (syncOption != null) {
            return options;
        }

        OpenOption[] tmp = new OpenOption[numOptions + 1];
        System.arraycopy(options, 0, tmp, 0, numOptions);
        tmp[numOptions] = StandardOpenOption.SYNC;
        if (log.isDebugEnabled()) {
            log.debug("resolveOpenOptions({}) modify options from {} to {} for {}",
                    session, Arrays.toString(options), Arrays.toString(tmp), file);
        }

        return tmp;
    }

    @Override
    public ScpSourceStreamResolver createScpSourceStreamResolver(Session session, Path path) throws IOException {
        return new LocalFileScpSourceStreamResolver(path, this);
    }

    @Override
    public ScpTargetStreamResolver createScpTargetStreamResolver(Session session, Path path) throws IOException {
        return new LocalFileScpTargetStreamResolver(path, this);
    }
}
