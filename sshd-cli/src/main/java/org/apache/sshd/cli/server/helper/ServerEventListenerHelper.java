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

package org.apache.sshd.cli.server.helper;

import java.io.Flushable;
import java.io.IOException;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;

public abstract class ServerEventListenerHelper implements NamedResource {
    private final String name;
    private final Appendable stdout;
    private final Appendable stderr;

    public ServerEventListenerHelper(String name, Appendable stdout, Appendable stderr) {
        this.name = name;
        this.stdout = Objects.requireNonNull(stdout, "No output target");
        this.stderr = Objects.requireNonNull(stderr, "No error target");
    }

    @Override
    public String getName() {
        return name;
    }

    public Appendable getStdout() {
        return stdout;
    }

    public Appendable getStderr() {
        return stderr;
    }

    protected String outputErrorMessage(String format, Object... args) throws IOException {
        return outputMessage(getStderr(), format, args);
    }

    protected String outputDebugMessage(String format, Object... args) throws IOException {
        return outputMessage(getStdout(), format, args);
    }

    protected String outputMessage(Appendable out, String format, Object... args) throws IOException {
        String message = String.format(format, args);
        out.append(getName())
            .append(": ").append(message)
            .append(System.lineSeparator());
        if (out instanceof Flushable) {
            ((Flushable) out).flush();
        }
        return message;
    }
}
