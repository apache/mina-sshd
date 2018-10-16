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
package org.apache.sshd.common;

/**
 * Exception used in the SSH client or server.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RuntimeSshException extends RuntimeException {
    private static final long serialVersionUID = -2423550196146939503L;

    public RuntimeSshException() {
        this(null, null);
    }

    public RuntimeSshException(String message) {
        this(message, null);
    }

    public RuntimeSshException(Throwable cause) {
        this(null, cause);
    }

    public RuntimeSshException(String message, Throwable cause) {
        super(message);
        if (cause != null) {
            initCause(cause);
        }
    }

}
