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
package org.apache.sshd.common.session.helpers;

/**
 * Special exception thrown by
 * {@link AbstractSession#attachSession(org.apache.sshd.common.io.IoSession, AbstractSession)} in order to indicate an
 * already attached I/O session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MultipleAttachedSessionException extends IllegalStateException {
    private static final long serialVersionUID = 4488792374797444445L;

    public MultipleAttachedSessionException(String s) {
        super(s);
    }

    public MultipleAttachedSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
