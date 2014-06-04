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
package org.apache.sshd.git.pgm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPgmCommand implements Command, Runnable {

    private String rootDir;
    private String command;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private ExitCallback callback;

    public GitPgmCommand(String rootDir, String command) {
        this.rootDir = rootDir;
        this.command = command;
    }

    public void setInputStream(InputStream in) {
        this.in = in;
    }

    public void setOutputStream(OutputStream out) {
        this.out = out;
        if (out instanceof ChannelOutputStream) {
            ((ChannelOutputStream) out).setNoDelay(true);
        }
    }

    public void setErrorStream(OutputStream err) {
        this.err = err;
        if (err instanceof ChannelOutputStream) {
            ((ChannelOutputStream) err).setNoDelay(true);
        }
    }

    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    public void start(Environment env) throws IOException {
        new Thread(this).start();
    }

    public void run() {
        try {
            List<String> strs = parseDelimitedString(command, " ", true);
            String[] args = strs.toArray(new String[strs.size()]);
            for (int i = 0; i < args.length; i++) {
                if (args[i].startsWith("'") && args[i].endsWith("'")) {
                    args[i] = args[i].substring(1, args[i].length() - 1);
                }
                if (args[i].startsWith("\"") && args[i].endsWith("\"")) {
                    args[i] = args[i].substring(1, args[i].length() - 1);
                }
            }

            new EmbeddedCommandRunner(rootDir).execute(args, in, out, err);
            if (callback != null) {
                callback.onExit(0);
            }
        } catch (Throwable t) {
            try {
                err.write((t.getMessage() + "\n").getBytes());
                err.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (callback != null) {
                callback.onExit(-1);
            }
        }
    }

    public void destroy() {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    /**
     * Parses delimited string and returns an array containing the tokens. This
     * parser obeys quotes, so the delimiter character will be ignored if it is
     * inside of a quote. This method assumes that the quote character is not
     * included in the set of delimiter characters.
     *
     * @param value the delimited string to parse.
     * @param delim the characters delimiting the tokens.
     * @return a list of string or an empty list if there are none.
     */
    private static List<String> parseDelimitedString(String value, String delim, boolean trim) {
        if (value == null) {
            value = "";
        }

        List<String> list = new ArrayList<String>();

        int CHAR = 1;
        int DELIMITER = 2;
        int STARTQUOTE = 4;
        int ENDQUOTE = 8;

        StringBuilder sb = new StringBuilder();

        int expecting = (CHAR | DELIMITER | STARTQUOTE);

        boolean isEscaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            boolean isDelimiter = (delim.indexOf(c) >= 0);

            if (!isEscaped && (c == '\\')) {
                isEscaped = true;
                continue;
            }

            if (isEscaped) {
                sb.append(c);
            } else if (isDelimiter && ((expecting & DELIMITER) > 0)) {
                if (trim) {
                    list.add(sb.toString().trim());
                } else {
                    list.add(sb.toString());
                }
                sb.delete(0, sb.length());
                expecting = (CHAR | DELIMITER | STARTQUOTE);
            } else if ((c == '"') && ((expecting & STARTQUOTE) > 0)) {
                sb.append(c);
                expecting = CHAR | ENDQUOTE;
            } else if ((c == '"') && ((expecting & ENDQUOTE) > 0)) {
                sb.append(c);
                expecting = (CHAR | STARTQUOTE | DELIMITER);
            } else if ((expecting & CHAR) > 0) {
                sb.append(c);
            } else {
                throw new IllegalArgumentException("Invalid delimited string: " + value);
            }

            isEscaped = false;
        }

        if (sb.length() > 0) {
            if (trim) {
                list.add(sb.toString().trim());
            } else {
                list.add(sb.toString());
            }
        }

        return list;
    }
}
