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
package org.apache.sshd.scp;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.apache.sshd.common.Property;

/**
 * Configurable properties for sshd-scp.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ScpModuleProperties {

    /**
     * Configurable value of the for controlling the wait timeout for opening a channel for an SCP command in
     * milliseconds.
     */
    public static final Property<Duration> SCP_EXEC_CHANNEL_OPEN_TIMEOUT
            = Property.duration("scp-exec-channel-open-timeout", Duration.ofSeconds(30));

    /**
     * Configurable value for controlling the wait timeout for waiting on a channel exit status' for an SCP command in
     * milliseconds. If non-positive, then no wait is performed and the command is assumed to have completed
     * successfully.
     */
    public static final Property<Duration> SCP_EXEC_CHANNEL_EXIT_STATUS_TIMEOUT
            = Property.duration("scp-exec-channel-exit-status-timeout", Duration.ofSeconds(5));

    /**
     * Whether to synchronize written file data with underlying file-system
     */
    public static final Property<Boolean> PROP_AUTO_SYNC_FILE_ON_WRITE
            = Property.bool("scp-auto-sync-on-write", true);

    /**
     * Used to indicate the {@link Charset} (or its name) for encoding referenced files/folders names - extracted from
     * the client channel session when 1st initialized.
     */
    public static final Property<Charset> NAME_ENCODING_CHARSET
            = Property.charset("scp-shell-name-encoding-charset", StandardCharsets.UTF_8);

    private ScpModuleProperties() {
        throw new UnsupportedOperationException("No instance");
    }
}
