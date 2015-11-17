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

package org.apache.sshd.server;

import java.io.IOException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface CommandLifecycle {
    /**
     * Starts the command execution. All streams must have been set <U>before</U>
     * calling this method. The command should implement {@link java.lang.Runnable},
     * and this method should spawn a new thread like:
     * <pre>
     * {@code Thread(this).start(); }
     * </pre>
     *
     * @param env The {@link Environment}
     * @throws IOException If failed to start
     */
    void start(Environment env) throws IOException;

    /**
     * This method is called by the SSH server to destroy the command because
     * the client has disconnected somehow.
     *
     * @throws Exception if failed to destroy
     */
    void destroy() throws Exception;
}
