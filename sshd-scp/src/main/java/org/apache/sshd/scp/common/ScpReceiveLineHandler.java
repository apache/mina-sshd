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

package org.apache.sshd.scp.common;

import java.io.IOException;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ScpReceiveLineHandler {
    /**
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  line        Received SCP input line
     * @param  isDir       Does the input line refer to a directory
     * @param  time        The received {@link ScpTimestampCommandDetails} - may be {@code null}
     * @throws IOException If failed to process the line
     */
    void process(Session session, String line, boolean isDir, ScpTimestampCommandDetails time) throws IOException;
}
