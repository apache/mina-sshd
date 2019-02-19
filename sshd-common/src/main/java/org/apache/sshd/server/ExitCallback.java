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

/**
 * Callback used by the shell to notify the SSH server is has exited
 */
@FunctionalInterface
public interface ExitCallback {

    /**
     * Informs the SSH server that the shell has exited
     *
     * @param exitValue the exit value
     */
    default void onExit(int exitValue) {
        onExit(exitValue, "");
    }

    /**
     * Informs the SSH client/server that the shell has exited
     *
     * @param exitValue   the exit value
     * @param exitMessage exit value description
     */
    void onExit(int exitValue, String exitMessage);
}
