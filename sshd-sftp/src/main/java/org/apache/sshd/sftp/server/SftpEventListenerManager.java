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

package org.apache.sshd.sftp.server;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpEventListenerManager {
    /**
     * @return An instance representing <U>all</U> the currently registered listeners. Any method invocation is
     *         <U>replicated</U> to the actually registered listeners
     */
    SftpEventListener getSftpEventListenerProxy();

    /**
     * Register a listener instance
     *
     * @param  listener The {@link SftpEventListener} instance to add - never {@code null}
     * @return          {@code true} if listener is a previously un-registered one
     */
    boolean addSftpEventListener(SftpEventListener listener);

    /**
     * Remove a listener instance
     *
     * @param  listener The {@link SftpEventListener} instance to remove - never {@code null}
     * @return          {@code true} if listener is a (removed) registered one
     */
    boolean removeSftpEventListener(SftpEventListener listener);
}
