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
package org.apache.sshd.server.command;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;

/**
 * This <code>CommandFactory</code> can be used as a standalone command factory
 * or can be used to augment another <code>CommandFactory</code> and provides
 * <code>SCP</code> support.
 *
 * @see ScpCommand
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommandFactory implements CommandFactory {

    private CommandFactory delegate;

    public ScpCommandFactory() {
    }

    public ScpCommandFactory(CommandFactory delegate) {
        this.delegate = delegate;
    }

    /**
     * Parses a command string and verifies that the basic syntax is
     * correct. If parsing fails the responsibility is delegated to
     * the configured {@link CommandFactory} instance; if one exist.
     *
     * @param command command to parse 
     * @return configured {@link Command} instance
     * @throws IllegalArgumentException
     */
    public Command createCommand(String command) {
        try {
            return new ScpCommand(splitCommandString(command));
        } catch (IllegalArgumentException iae) {
            if (delegate != null) {
                return delegate.createCommand(command);
            }
            throw iae;
        }
    }

    private String[] splitCommandString(String command) {
        if (!command.trim().startsWith("scp")) {
            throw new IllegalArgumentException("Unknown command, does not begin with 'scp'");
        }

        String[] args = command.split(" ");
        List<String> parts = new ArrayList<String>();
        parts.add(args[0]);
        for (int i = 1; i < args.length; i++) {
            if (!args[i].trim().startsWith("-")) {
                parts.add(concatenateWithSpace(args, i));
                break;
            } else {
                parts.add(args[i]);
            }
        }
        return parts.toArray(new String[parts.size()]);
    }

    private String concatenateWithSpace(String[] args, int from) {
        StringBuilder sb = new StringBuilder();

        for (int i = from; i < args.length; i++) {
            sb.append(args[i] + " ");
        }
        return sb.toString().trim();
    }
}
