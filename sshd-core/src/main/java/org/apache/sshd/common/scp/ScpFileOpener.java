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

package org.apache.sshd.common.scp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.OpenOption;
import java.nio.file.Path;

import org.apache.sshd.common.session.Session;

/**
 * Plug-in mechanism for users to intervene in the SCP process - e.g.,
 * apply some kind of traffic shaping mechanism, display upload/download
 * progress, etc...
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpFileOpener {
    /**
     * Create an input stream to read from a file
     *
     * @param session The {@link Session} requesting the access
     * @param file The requested local file {@link Path}
     * @param options The {@link OpenOption}s - may be {@code null}/empty
     * @return The open {@link InputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    InputStream openRead(Session session, Path file, OpenOption... options) throws IOException;

    /**
     * Create an output stream to write to a file
     *
     * @param session The {@link Session} requesting the access
     * @param file The requested local file {@link Path}
     * @param options The {@link OpenOption}s - may be {@code null}/empty
     * @return The open {@link OutputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    OutputStream openWrite(Session session, Path file, OpenOption... options) throws IOException;
}
