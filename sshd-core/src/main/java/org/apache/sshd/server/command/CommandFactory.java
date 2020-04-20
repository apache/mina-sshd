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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.channel.ChannelSession;

/**
 * Commands are executed on the server side when an &quot;exec&quot; channel is requested by the SSH client.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface CommandFactory {
    /**
     * Create a command with the given name. If the command is not known, a dummy command should be returned to allow
     * the display output to be sent back to the client.
     *
     * @param  channel     The {@link ChannelSession} through which the command has been received
     * @param  command     The command that will be run
     * @return             a non {@code null} {@link Command} instance
     * @throws IOException if failed to create the instance
     */
    Command createCommand(ChannelSession channel, String command) throws IOException;

    /**
     * @param  command The raw command - ignored if {@code null}/empty
     * @return         The parsed command elements while stripping quoted arguments
     */
    static List<String> split(String command) {
        int len = GenericUtils.length(command);
        if (len <= 0) {
            return Collections.emptyList();
        }

        int curPos = command.indexOf(' ');
        if (curPos < 0) {
            return Collections.singletonList(command);
        }

        int lastPos = 0;
        List<String> elements = new ArrayList<>();
        for (curPos = 0; curPos < len; curPos++) {
            char ch = command.charAt(curPos);
            // delimited element ?
            if (((ch == '\'') || (ch == '"'))
                    // not last character
                    && (curPos < (len - 1))
                    // either 1st character or preceded by space
                    && ((curPos == 0) || (command.charAt(curPos - 1) == ' '))) {
                // find matching delimiter
                int nextPos = command.indexOf(ch, curPos + 1);
                if (nextPos <= curPos) {
                    continue; // if not found assume unquoted
                }

                String elem = command.substring(curPos + 1, nextPos);
                elements.add(elem);

                curPos = nextPos;
            } else if (ch != ' ') {
                continue;
            } else {
                if (lastPos < curPos) {
                    String elem = command.substring(lastPos, curPos);
                    elements.add(elem);
                }
            }

            // skip space and any sequence of them
            for (curPos++; curPos < len; curPos++) {
                ch = command.charAt(curPos);
                if (ch != ' ') {
                    break;
                }
            }

            lastPos = curPos;
            curPos--; // compensate for loop auto-increment
        }

        // any trailing element ?
        if (lastPos < len) {
            String elem = command.substring(lastPos);
            elements.add(elem);
        }

        return elements;
    }
}
