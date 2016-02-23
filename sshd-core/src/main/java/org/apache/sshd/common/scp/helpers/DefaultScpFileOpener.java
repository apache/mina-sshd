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

package org.apache.sshd.common.scp.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Arrays;

import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpFileOpener extends AbstractLoggingBean implements ScpFileOpener {
    public static final DefaultScpFileOpener INSTANCE = new DefaultScpFileOpener();

    public DefaultScpFileOpener() {
        super();
    }

    @Override
    public InputStream openRead(Session session, Path file, OpenOption... options) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("openRead({}) file={}, options={}",
                      session, file, Arrays.toString(options));
        }

        return Files.newInputStream(file, options);
    }

    @Override
    public OutputStream openWrite(Session session, Path file, OpenOption... options) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("openWrite({}) file={}, options={}",
                      session, file, Arrays.toString(options));
        }

        return Files.newOutputStream(file, options);
    }
}
