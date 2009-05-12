/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common;

import java.io.IOException;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshException extends IOException {

    private final int disconnectCode;

    public SshException() {
        this(0, null, null);
    }

    public SshException(String message) {
        this(0, message, null);
    }

    public SshException(String message, Throwable cause) {
        this(0, message, cause);
    }

    public SshException(Throwable cause) {
        this(0, null, cause);
    }

    public SshException(int disconnectCode) {
        this(disconnectCode, null, null);
    }

    public SshException(int disconnectCode, String message) {
        this(disconnectCode, message, null);
    }

    public SshException(int disconnectCode, Throwable cause) {
        this(disconnectCode, null, cause);
    }

    public SshException(int disconnectCode, String message, Throwable cause) {
        super(message);
        this.disconnectCode = disconnectCode;
        if (cause != null) {
            initCause(cause);
        }
    }

    public int getDisconnectCode() {
        return disconnectCode;
    }
}
