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

package org.apache.sshd.common.compression;

import org.apache.sshd.common.NamedResource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface CompressionInformation extends NamedResource {
    /**
     * Delayed compression is an Open-SSH specific feature which informs both the client and server to not compress data
     * before the session has been authenticated.
     *
     * @return if the compression is delayed after authentication or not
     */
    boolean isDelayed();

    /**
     * @return {@code true} if there is any compression executed by this &quot;compressor&quot; - special case for
     *         'none'
     */
    boolean isCompressionExecuted();
}
