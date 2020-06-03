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
package org.apache.sshd.server.scp;

import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.sshd.common.scp.ScpException;
import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.scp.helpers.DefaultScpFileOpener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AbstractFileSystemCommand;

/**
 * This commands SCP support for a ChannelSession.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpShell extends AbstractFileSystemCommand {

    public static final String STATUS = "status";

    protected static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    protected static final List<String> WINDOWS_EXECUTABLE_EXTENSIONS
            = Collections.unmodifiableList(Arrays.asList(".bat", ".exe", ".cmd"));
    protected static final LinkOption[] EMPTY_LINK_OPTIONS = new LinkOption[0];

    protected final ChannelSession channel;
    protected ScpFileOpener opener;
    protected ScpTransferEventListener listener;
    protected int sendBufferSize;
    protected int receiveBufferSize;
    protected Path currentDir;
    protected Map<String, Object> variables = new HashMap<>();

    public ScpShell(ChannelSession channel, CloseableExecutorService executorService,
                    int sendSize, int receiveSize,
                    ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        super(null, executorService);
        this.channel = channel;

        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpShell> send buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }
        sendBufferSize = sendSize;

        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpCommmand> receive buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;

        opener = (fileOpener == null) ? DefaultScpFileOpener.INSTANCE : fileOpener;
        listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;

    }

    protected void println(Object x, OutputStream out) {
        try {
            String s = x + System.lineSeparator();
            out.write(s.getBytes());
        } catch (IOException e) {
            throw new IOError(e);
        }
    }

    @Override
    public void run() {
        String command = null;
        try {
            currentDir = opener.resolveLocalPath(channel.getSession(), fileSystem, ".");
            // Use a special stream reader so that the stream can be used with the scp command
            try (Reader r = new InputStreamReader(getInputStream(), StandardCharsets.UTF_8)) {
                for (;;) {
                    command = readLine(r);
                    if (command.length() == 0 || !handleCommandLine(command)) {
                        return;
                    }
                }
            }
        } catch (InterruptedIOException e) {
            // Ignore - signaled end
        } catch (Exception e) {
            String message = "Failed (" + e.getClass().getSimpleName() + ") to handle '" + command + "': " + e.getMessage();
            try {
                OutputStream stderr = getErrorStream();
                stderr.write(message.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ioe) {
                log.warn("Failed ({}) to write error message={}: {}",
                        e.getClass().getSimpleName(), message, ioe.getMessage());
            } finally {
                onExit(-1, message);
            }
        } finally {
            onExit(0);
        }
    }

    protected String readLine(Reader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int c = reader.read();
            if (c < 0 || c == '\n') {
                break;
            }
            sb.append((char) c);
        }
        return sb.toString();
    }

    protected boolean handleCommandLine(String command) throws Exception {
        List<String[]> cmds = parse(command);
        for (String[] argv : cmds) {
            switch (argv[0]) {
                case "echo":
                    echo(argv);
                    break;
                case "pwd":
                    pwd(argv);
                    break;
                case "cd":
                    cd(argv);
                    break;
                case "ls":
                    ls(argv);
                    break;
                case "scp":
                    scp(argv);
                    break;
                case "groups":
                    variables.put(STATUS, 0);
                    break;
                case "unset":
                case "unalias":
                case "printenv":
                    variables.put(STATUS, 1);
                    break;
                default:
                    variables.put(STATUS, 127);
                    getErrorStream().write(("command not found: " + argv[0] + "\n").getBytes());
            }
            getOutputStream().flush();
            getErrorStream().flush();
        }
        return true;
    }

    protected List<String[]> parse(String command) {
        List<String[]> cmds = new ArrayList<>();
        List<String> args = new ArrayList<>();
        StringBuilder arg = new StringBuilder();
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < command.length(); i++) {
            char ch = command.charAt(i);
            if (escaped) {
                arg.append(ch);
                escaped = false;
            } else if (ch == quote) {
                quote = 0;
            } else if (ch == '"' || ch == '\'') {
                quote = ch;
            } else if (ch == '\\') {
                escaped = true;
            } else if (quote == 0 && Character.isWhitespace(ch)) {
                if (arg.length() > 0) {
                    args.add(arg.toString());
                    arg.setLength(0);
                }
            } else if (quote == 0 && ch == ';') {
                if (arg.length() > 0) {
                    args.add(arg.toString());
                    arg.setLength(0);
                }
                if (!args.isEmpty()) {
                    cmds.add(args.toArray(new String[0]));
                }
                args.clear();
            } else {
                arg.append(ch);
            }
        }
        if (arg.length() > 0) {
            args.add(arg.toString());
            arg.setLength(0);
        }
        if (!args.isEmpty()) {
            cmds.add(args.toArray(new String[0]));
        }
        return cmds;
    }

    protected void scp(String[] argv) throws Exception {
        boolean optR = false;
        boolean optT = false;
        boolean optF = false;
        boolean optD = false;
        boolean optP = false;
        boolean isOption = true;
        String path = null;
        for (int i = 1; i < argv.length; i++) {
            if (isOption && argv[i].startsWith("-")) {
                switch (argv[i]) {
                    case "-r":
                        optR = true;
                        break;
                    case "-t":
                        optT = true;
                        break;
                    case "-f":
                        optF = true;
                        break;
                    case "-d":
                        optD = true;
                        break;
                    case "-p":
                        optP = true;
                        break;
                    default:
                        println("scp: unsupported option: " + argv[i], getErrorStream());
                        variables.put(STATUS, 1);
                        return;
                }
            } else if (path == null) {
                path = argv[i];
                isOption = false;
            } else {
                println("scp: one and only one argument expected", getErrorStream());
                variables.put(STATUS, 1);
                return;
            }
        }
        if (optT && optF || !optT && !optF) {
            println("scp: one and only one of -t and -f option expected", getErrorStream());
            variables.put(STATUS, 1);
        } else {
            try {
                ScpHelper helper = new ScpHelper(
                        channel.getSession(), getInputStream(), getOutputStream(),
                        fileSystem, opener, listener);
                if (optT) {
                    helper.receive(helper.resolveLocalPath(path), optR, optD, optP, receiveBufferSize);
                } else {
                    helper.send(Collections.singletonList(path), optR, optP, sendBufferSize);
                }
                variables.put(STATUS, 0);
            } catch (IOException e) {
                Integer statusCode = e instanceof ScpException ? ((ScpException) e).getExitStatus() : null;
                int exitValue = (statusCode == null) ? ScpHelper.ERROR : statusCode;
                // this is an exception so status cannot be OK/WARNING
                if ((exitValue == ScpHelper.OK) || (exitValue == ScpHelper.WARNING)) {
                    exitValue = ScpHelper.ERROR;
                }
                String exitMessage = GenericUtils.trimToEmpty(e.getMessage());
                ScpHelper.sendResponseMessage(getOutputStream(), exitValue, exitMessage);
                variables.put(STATUS, exitValue);
            }
        }
    }

    protected void echo(String[] argv) throws Exception {
        StringBuilder buf = new StringBuilder();
        for (int k = 1; k < argv.length; k++) {
            String arg = argv[k];
            if (buf.length() > 0) {
                buf.append(' ');
            }
            int vstart = -1;
            for (int i = 0; i < arg.length(); i++) {
                int c = arg.charAt(i);
                if (vstart >= 0) {
                    if (c != '_' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z')) {
                        if (vstart == i) {
                            buf.append('$');
                        } else {
                            String n = arg.substring(vstart, i);
                            Object v = variables.get(n);
                            if (v != null) {
                                buf.append(v);
                            }
                        }
                        vstart = -1;
                    }
                } else if (c == '$') {
                    vstart = i + 1;
                } else {
                    buf.append((char) c);
                }
            }
            if (vstart >= 0) {
                String n = arg.substring(vstart);
                if (n.isEmpty()) {
                    buf.append('$');
                } else {
                    Object v = variables.get(n);
                    if (v != null) {
                        buf.append(v);
                    }
                }
            }
        }
        println(buf, getOutputStream());
        variables.put(STATUS, 0);
    }

    protected void pwd(String[] argv) throws Exception {
        if (argv.length != 1) {
            println("pwd: too many arguments", getErrorStream());
            variables.put(STATUS, 1);
        } else {
            println(currentDir, getOutputStream());
            variables.put(STATUS, 0);
        }
    }

    protected void cd(String[] argv) throws Exception {
        if (argv.length != 2) {
            println("cd: too many or too few arguments", getErrorStream());
            variables.put(STATUS, 1);
        } else {
            Path cwd = currentDir;
            String path = argv[1];
            cwd = cwd.resolve(path).toAbsolutePath().normalize();
            if (!Files.exists(cwd)) {
                println("no such file or directory: " + path, getErrorStream());
                variables.put(STATUS, 1);
            } else if (!Files.isDirectory(cwd)) {
                println("not a directory: " + path, getErrorStream());
                variables.put(STATUS, 1);
            } else {
                currentDir = cwd;
                variables.put(STATUS, 0);
            }
        }
    }

    protected void ls(String[] argv) throws Exception {
        // find options
        boolean a = false;
        boolean l = false;
        boolean f = false;
        for (int k = 1; k < argv.length; k++) {
            if (argv[k].equals("--full-time")) {
                f = true;
            } else if (argv[k].startsWith("-")) {
                for (int i = 1; i < argv[k].length(); i++) {
                    switch (argv[k].charAt(i)) {
                        case 'a':
                            a = true;
                            break;
                        case 'l':
                            l = true;
                            break;
                        default:
                            println("unsupported option: -" + argv[k].charAt(i), getErrorStream());
                            variables.put(STATUS, 1);
                            return;
                    }
                }
            } else {
                println("unsupported option: " + argv[k], getErrorStream());
                variables.put(STATUS, 1);
                return;
            }
        }
        boolean optListAll = a;
        boolean optLong = l;
        boolean optFullTime = f;
        // list current directory content
        Predicate<Path> filter = p -> optListAll || p.getFileName().toString().equals(".")
                || p.getFileName().toString().equals("..") || !p.getFileName().toString().startsWith(".");
        String[] synth = currentDir.toString().equals("/") ? new String[] { "." } : new String[] { ".", ".." };
        Stream.concat(Stream.of(synth).map(currentDir::resolve), Files.list(currentDir))
                .filter(filter)
                .map(p -> new PathEntry(p, currentDir))
                .sorted()
                .map(p -> p.display(optLong, optFullTime))
                .forEach(str -> println(str, getOutputStream()));
        variables.put(STATUS, 0);
    }

    protected static class PathEntry implements Comparable<PathEntry> {

        protected final Path abs;
        protected final Path path;
        protected final Map<String, Object> attributes;

        public PathEntry(Path abs, Path root) {
            this.abs = abs;
            this.path = abs.startsWith(root) ? root.relativize(abs) : abs;
            this.attributes = readAttributes(abs);
        }

        @Override
        public int compareTo(PathEntry o) {
            return path.toString().compareTo(o.path.toString());
        }

        public String display(boolean optLongDisplay, boolean optFullTime) {
            if (optLongDisplay) {
                String username;
                if (attributes.containsKey("owner")) {
                    username = Objects.toString(attributes.get("owner"), null);
                } else {
                    username = "owner";
                }
                if (username.length() > 8) {
                    username = username.substring(0, 8);
                } else {
                    for (int i = username.length(); i < 8; i++) {
                        username += " ";
                    }
                }
                String group;
                if (attributes.containsKey("group")) {
                    group = Objects.toString(attributes.get("group"), null);
                } else {
                    group = "group";
                }
                if (group.length() > 8) {
                    group = group.substring(0, 8);
                } else {
                    for (int i = group.length(); i < 8; i++) {
                        group += " ";
                    }
                }
                Number length = (Number) attributes.get("size");
                if (length == null) {
                    length = 0L;
                }
                String lengthString = String.format("%1$8s", length);
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission> perms = (Set<PosixFilePermission>) attributes.get("permissions");
                if (perms == null) {
                    perms = EnumSet.noneOf(PosixFilePermission.class);
                }
                // TODO: all fields should be padded to align
                return is("isDirectory")
                        ? "d" : (is("isSymbolicLink") ? "l" : (is("isOther") ? "o" : "-"))
                                + PosixFilePermissions.toString(perms) + " "
                                + String.format("%3s",
                                        attributes.containsKey("nlink") ? attributes.get("nlink").toString() : "1")
                                + " " + username + " " + group + " " + lengthString + " "
                                + toString((FileTime) attributes.get("lastModifiedTime"), optFullTime)
                                + " " + shortDisplay();
            } else {
                return shortDisplay();
            }
        }

        protected boolean is(String attr) {
            Object d = attributes.get(attr);
            return d instanceof Boolean && (Boolean) d;
        }

        protected String shortDisplay() {
            if (is("isSymbolicLink")) {
                try {
                    Path l = Files.readSymbolicLink(abs);
                    return path.toString() + " -> " + l.toString();
                } catch (IOException e) {
                    // ignore
                }
            }
            return path.toString();
        }

        protected String toString(FileTime time, boolean optFullTime) {
            long millis = (time != null) ? time.toMillis() : -1L;
            if (millis < 0L) {
                return "------------";
            }
            ZonedDateTime dt = Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault());
            if (optFullTime) {
                return DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss yyyy").format(dt);
            } else if (System.currentTimeMillis() - millis < 183L * 24L * 60L * 60L * 1000L) {
                return DateTimeFormatter.ofPattern("MMM ppd HH:mm").format(dt);
            } else {
                return DateTimeFormatter.ofPattern("MMM ppd  yyyy").format(dt);
            }
        }

        protected static Map<String, Object> readAttributes(Path path) {
            Map<String, Object> attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (String view : path.getFileSystem().supportedFileAttributeViews()) {
                try {
                    Map<String, Object> ta = Files.readAttributes(path, view + ":*", EMPTY_LINK_OPTIONS);
                    ta.forEach(attrs::putIfAbsent);
                } catch (IOException e) {
                    // Ignore
                }
            }
            attrs.computeIfAbsent("isExecutable", s -> Files.isExecutable(path));
            attrs.computeIfAbsent("permissions", s -> getPermissionsFromFile(path.toFile()));
            return attrs;
        }
    }

    /**
     * @param  f The {@link File} to be checked
     * @return   A {@link Set} of {@link PosixFilePermission}s based on whether the file is
     *           readable/writable/executable. If so, then <U>all</U> the relevant permissions are set (i.e., owner,
     *           group and others)
     */
    protected static Set<PosixFilePermission> getPermissionsFromFile(File f) {
        Set<PosixFilePermission> perms = EnumSet.noneOf(PosixFilePermission.class);
        if (f.canRead()) {
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.OTHERS_READ);
        }

        if (f.canWrite()) {
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.OTHERS_WRITE);
        }

        if (f.canExecute() || (IS_WINDOWS && isWindowsExecutable(f.getName()))) {
            perms.add(PosixFilePermission.OWNER_EXECUTE);
            perms.add(PosixFilePermission.GROUP_EXECUTE);
            perms.add(PosixFilePermission.OTHERS_EXECUTE);
        }

        return perms;
    }

    /**
     * @param  fileName The file name to be evaluated - ignored if {@code null}/empty
     * @return          {@code true} if the file ends in one of the {@link #WINDOWS_EXECUTABLE_EXTENSIONS}
     */
    protected static boolean isWindowsExecutable(String fileName) {
        if ((fileName == null) || (fileName.length() <= 0)) {
            return false;
        }
        for (String suffix : WINDOWS_EXECUTABLE_EXTENSIONS) {
            if (fileName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

}
