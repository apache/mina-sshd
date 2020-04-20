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
package org.apache.sshd.server.command;

import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;

/**
 * Represents a command capable of doing non-blocking io. If this interface is implemented by a command, the usual
 * blocking input / output / error streams won't be set.
 */
public interface AsyncCommand extends Command {

    /**
     * Set the input stream that can be used by the shell to read input.
     *
     * @param in The {@link IoInputStream} used by the shell to read input
     */
    void setIoInputStream(IoInputStream in);

    /**
     * Set the output stream that can be used by the shell to write its output.
     *
     * @param out The {@link IoOutputStream} used by the shell to write its output
     */
    void setIoOutputStream(IoOutputStream out);

    /**
     * Set the error stream that can be used by the shell to write its errors.
     *
     * @param err The {@link IoOutputStream} used by the shell to write its errors
     */
    void setIoErrorStream(IoOutputStream err);

}
