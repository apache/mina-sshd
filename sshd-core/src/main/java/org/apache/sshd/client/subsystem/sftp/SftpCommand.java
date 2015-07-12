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

package org.apache.sshd.client.subsystem.sftp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.channels.Channel;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.subsystem.sftp.extensions.ParserUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;

/**
 * Implements a simple command line SFTP client similar to the Linux one
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpCommand implements Channel {
    private final SftpClient client;
    private String cwdRemote;
    private final Map<String,CommandExecutor> commandsMap = 
            Collections.unmodifiableMap(new TreeMap<String,CommandExecutor>() {
                private static final long serialVersionUID = 1L;    // we're not serializing it
                
                {
                    for (CommandExecutor e : Arrays.<CommandExecutor>asList(
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "exit";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
                                            stdout.println("Exiting");
                                            return true;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "pwd";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
                                            stdout.append('\t').println(getCurrentRemoteDirectory());
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "info";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
                                            SftpClient sftp = getClient();
                                            Map<String,byte[]> extensions = sftp.getServerExtensions();
                                            Map<String,?> parsed = ParserUtils.parse(extensions);
                                            for (Map.Entry<String,byte[]> ee : extensions.entrySet()) {
                                                String name = ee.getKey();
                                                byte[] value = ee.getValue();
                                                Object info  = parsed.get(name);

                                                stdout.append('\t').append(name).append(": ");
                                                if (info == null) {
                                                    stdout.println(BufferUtils.printHex(value));
                                                } else {
                                                    stdout.println(info);
                                                }
                                            }
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "version";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
                                            SftpClient sftp = getClient();
                                            stdout.append('\t').println(sftp.getVersion());
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "cd";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified", args);

                                            String newPath = resolveRemotePath(args);
                                            SftpClient sftp = getClient();
                                            setCurrentRemoteDirectory(sftp.canonicalPath(newPath));
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "mkdir";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified", args);

                                            String path = resolveRemotePath(args);
                                            SftpClient sftp = getClient();
                                            sftp.mkdir(path);
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "ls";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            String[] comps = GenericUtils.split(args, ' ');
                                            // ignore all flag
                                            String pathArg = GenericUtils.isEmpty(comps) ? null : comps[comps.length - 1];
                                            String cwd = getCurrentRemoteDirectory();
                                            if (GenericUtils.isEmpty(pathArg) || (pathArg.charAt(0) == '-')) {
                                                pathArg = cwd;
                                            }

                                            String path = resolveRemotePath(pathArg);
                                            SftpClient sftp = getClient();
                                            for (SftpClient.DirEntry entry : sftp.readDir(path)) {
                                                SftpClient.Attributes attrs = entry.attributes;
                                                stdout.append('\t').append(entry.filename)
                                                      .append('\t').append(Long.toString(attrs.size))
                                                      .append('\t').println(SftpFileSystemProvider.getRWXPermissions(attrs.perms));
                                            }
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "rm";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified", args);

                                            String path = resolveRemotePath(args);
                                            SftpClient sftp = getClient();
                                            sftp.remove(path);
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "rmdir";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified", args);

                                            String path = resolveRemotePath(args);
                                            SftpClient sftp = getClient();
                                            sftp.rmdir(path);
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "rename";
                                        }
    
                                        @Override
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            String[] comps = GenericUtils.split(args, ' ');
                                            ValidateUtils.checkTrue(GenericUtils.length(comps) == 2, "Invalid number of arguments: %s", args);

                                            String oldPath = resolveRemotePath(comps[0]);
                                            String newPath = resolveRemotePath(comps[1]);
                                            SftpClient sftp = getClient();
                                            sftp.rename(oldPath, newPath);
                                            return false;
                                        }
                                    },
                                new CommandExecutor() {
                                        @Override
                                        public String getName() {
                                            return "help";
                                        }
    
                                        @Override
                                        @SuppressWarnings("synthetic-access")
                                        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
                                            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
                                            for (String cmd : commandsMap.keySet()) {
                                                stdout.append('\t').println(cmd);
                                            }
                                            return false;
                                        }
                                    }
                            )) {
                        put(e.getName(), e);
                    }
                }
            });

    public SftpCommand(SftpClient client) {
        this.client = ValidateUtils.checkNotNull(client, "No client", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    public final SftpClient getClient() {
        return client;
    }

    public void doInteractive(BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
        SftpClient sftp = getClient();
        setCurrentRemoteDirectory(sftp.canonicalPath("."));
        while(true) {
            stdout.append(getCurrentRemoteDirectory()).append(" > ").flush();
            String line = stdin.readLine();
            if (line == null) { // EOF
                break;
            }
            
            line = line.trim();
            if (GenericUtils.isEmpty(line)) {
                continue;
            }
            
            String cmd, args;
            int pos = line.indexOf(' ');
            if (pos > 0) {
                cmd = line.substring(0, pos);
                args = line.substring(pos + 1).trim();
            } else {
                cmd = line;
                args = "";
            }
            
            CommandExecutor exec = commandsMap.get(cmd);
            try {
                if (exec == null) {
                    stderr.append("Unknown command: ").println(line);
                } else {
                    try {
                        if (exec.executeCommand(args, stdin, stdout, stderr)) {
                            break;
                        }
                    } catch(Exception e) {
                        stderr.append(e.getClass().getSimpleName()).append(": ").println(e.getMessage());
                    } finally {
                        stdout.flush();
                    }
                }
            } finally {
                stderr.flush(); // just makings sure
            }
        }
    }

    protected String resolveRemotePath(String pathArg) {
        String cwd = getCurrentRemoteDirectory();
        if (GenericUtils.isEmpty(pathArg)) {
            return cwd;
        }
        
        if (pathArg.charAt(0) == '/') {
            return pathArg;
        } else {
            return cwd + "/" + pathArg;
        }
    }
    public String getCurrentRemoteDirectory() {
        return cwdRemote;
    }

    public void setCurrentRemoteDirectory(String path) {
        cwdRemote = path;
    }

    @Override
    public boolean isOpen() {
        return client.isOpen();
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            client.close();
        }
    }

    public static interface CommandExecutor extends NamedResource {
        // return value is whether to stop running
        boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception; 
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        PrintStream stdout=System.out, stderr=System.err;
        try(BufferedReader stdin = new BufferedReader(new InputStreamReader(new NoCloseInputStream(System.in)))) {
            ClientSession session=SshClient.setupClientSession("-P", stdin, stdout, stderr, args);
            if (session == null) {
                System.err.println("usage: sftp [-l login] [-P port] [-o option=value] hostname/user@host");
                System.exit(-1);
                return;
            }
            
            try(SshClient client = (SshClient) session.getFactoryManager()) {
                try(SftpCommand sftp = new SftpCommand(session.createSftpClient())) {
                    sftp.doInteractive(stdin, stdout, stderr);
                }
            } finally {
                session.close();
            }
        }
    }
}
