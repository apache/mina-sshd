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
package org.apache.sshd.scp.server;

import java.io.IOError;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.scp.ScpModuleProperties;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AbstractFileSystemCommand;

/**
 * This commands SCP support for a ChannelSession.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpShell extends AbstractFileSystemCommand {

    public static final String STATUS = "status";

    /** The &quot;PWD&quot; environment variable */
    public static final String ENV_PWD = "PWD";

    /** The &quot;HOME&quot; environment variable */
    public static final String ENV_HOME = "HOME";

    /**
     * Key for the language - format &quot;en_US.UTF-8&quot;
     */
    public static final String ENV_LANG = "LANG";

    protected final ChannelSession channel;
    protected final Map<String, Object> variables = new HashMap<>();
    protected final Charset nameEncodingCharset;

    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;
    protected final int sendBufferSize;
    protected final int receiveBufferSize;
    protected Path currentDir;
    protected Path homeDir;

    public ScpShell(ChannelSession channel, CloseableExecutorService executorService,
                    int sendSize, int receiveSize,
                    ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        super(null, executorService);
        this.channel = channel;

        nameEncodingCharset = ScpModuleProperties.NAME_ENCODING_CHARSET.getRequired(channel);

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

    @Override
    public void setFileSystemFactory(FileSystemFactory factory, SessionContext session) throws IOException {
        homeDir = factory.getUserHomeDir(session);
        super.setFileSystemFactory(factory, session);
    }

    protected void println(String cmd, Object x, OutputStream out, Charset cs) {
        try {
            String s = x.toString();
            if (log.isDebugEnabled()) {
                log.debug("println({})[{}]: {}",
                        channel, cmd, s.replace('\n', ' ').replace('\t', ' '));
            }
            out.write(s.getBytes(cs));
            // always write LF even if running on Windows
            out.write('\n');
        } catch (IOException e) {
            throw new IOError(e);
        }
    }

    protected void signalError(String cmd, String errorMsg) {
        signalError(cmd, errorMsg, StandardCharsets.US_ASCII);
    }

    protected void signalError(String cmd, String errorMsg, Charset cs) {
        log.warn("{}[{}]: {}", channel, cmd, errorMsg);
        println(cmd, errorMsg, getErrorStream(), cs);
        variables.put(STATUS, 1);
    }

    @Override
    public void run() {
        String command = null;
        variables.put(STATUS, 0);

        boolean debugEnabled = log.isDebugEnabled();
        try {
            // TODO find some better alternative
            if (homeDir == null) {
                currentDir = opener.resolveLocalPath(channel.getSession(), fileSystem, ".");
                log.warn("run - no home dir - starting at {}", currentDir);
            } else {
                currentDir = homeDir;
                if (debugEnabled) {
                    log.debug("run - starting at home dir={}", homeDir);
                }
            }

            prepareEnvironment(getEnvironment());

            // Use a special stream reader so that the stream can be used with the scp command
            try (Reader r = new InputStreamReader(getInputStream(), StandardCharsets.UTF_8)) {
                for (int executedCommands = 0;; executedCommands++) {
                    command = readLine(r);
                    if (GenericUtils.isEmpty(command)) {
                        if (debugEnabled) {
                            log.debug("run({}) Command loop terminated after {} commands", channel, executedCommands);
                        }

                        return;
                    }

                    if (!handleCommandLine(command)) {
                        if (debugEnabled) {
                            log.debug("run({}) Command loop terminated by cmd={} after {} commands",
                                    channel, command, executedCommands);
                        }
                        return;
                    }
                }
            }
        } catch (InterruptedIOException e) {
            if (debugEnabled) {
                log.debug("run({}) interrupted after command={}", channel, command);
            }
        } catch (Exception e) {
            String message = "Failed (" + e.getClass().getSimpleName() + ") to handle '" + command + "': " + e.getMessage();
            log.warn("run({}) {}", channel, message);
            try {
                OutputStream stderr = getErrorStream();
                stderr.write(message.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ioe) {
                log.warn("run({}) Failed ({}) to write error message={}: {}",
                        channel, ioe.getClass().getSimpleName(), message, ioe.getMessage());
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
            if ((c < 0) || c == '\n') {
                break;
            }
            sb.append((char) c);
        }

        int len = sb.length();
        // Strip CR at end of line if present
        if ((len > 0) && (sb.charAt(len - 1) == '\r')) {
            sb.setLength(len - 1);
        }

        return sb.toString();
    }

    protected boolean handleCommandLine(String command) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleCommandLine({}) {}", channel, command);
        }

        List<String[]> cmds = parse(command);
        OutputStream stdout = getOutputStream();
        OutputStream stderr = getErrorStream();
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
                case "printenv":
                    printenv(argv);
                    break;
                case "unset":
                    unset(argv);
                    break;
                case "unalias":
                    variables.put(STATUS, 1);
                    break;
                default:
                    handleUnsupportedCommand(command, argv);
            }
            stdout.flush();
            stderr.flush();
        }

        return true;
    }

    protected void prepareEnvironment(Environment environ) {
        Map<String, String> env = environ.getEnv();
        Locale locale = Locale.getDefault();
        String languageTag = locale.toLanguageTag();
        env.put(ENV_LANG, languageTag.replace('-', '_') + "." + nameEncodingCharset.displayName());

        if (homeDir != null) {
            env.put(ENV_HOME, homeDir.toString());
        }

        updatePwdEnvVariable(currentDir);
    }

    protected void handleUnsupportedCommand(String command, String[] argv) throws Exception {
        log.warn("handleUnsupportedCommand({}) unsupported: {}", channel, command);
        variables.put(STATUS, 127);
        getErrorStream().write(("command not found: " + argv[0] + "\n").getBytes(StandardCharsets.US_ASCII));
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

    protected void printenv(String[] argv) throws Exception {
        Environment environ = getEnvironment();
        Map<String, String> envValues = environ.getEnv();
        OutputStream stdout = getOutputStream();
        if (argv.length == 1) {
            envValues.entrySet()
                    .stream()
                    .forEach(e -> println(argv[0], e.getKey() + "=" + e.getValue(), stdout, StandardCharsets.US_ASCII));
            variables.put(STATUS, 0);
            return;
        }

        if (argv.length != 2) {
            signalError(argv[0], "printenv: only one variable value at a time");
            return;
        }

        String varName = argv[1];
        String varValue = resolveEnvironmentVariable(varName, envValues);
        if (varValue == null) {
            signalError(argv[0], "printenv: variable not set " + varName);
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("printenv({}) {}={}", channel, varName, varValue);
        }

        println(argv[0], varValue, stdout, StandardCharsets.US_ASCII);
        variables.put(STATUS, 0);
    }

    protected String resolveEnvironmentVariable(String varName, Map<String, String> envValues) {
        return envValues.get(varName);
    }

    protected void unset(String[] argv) throws Exception {
        if (argv.length != 2) {
            signalError(argv[0], "unset: exactly one argument is expected");
            return;
        }

        Environment environ = getEnvironment();
        Map<String, String> envValues = environ.getEnv();
        String varName = argv[1];
        String varValue = envValues.remove(varName);
        if (log.isDebugEnabled()) {
            log.debug("unset({}) {}={}", channel, varName, varValue);
        }
        variables.put(STATUS, (varValue == null) ? 1 : 0);
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
            String argVal = argv[i];
            if (GenericUtils.isEmpty(argVal)) {
                signalError(argv[0], "scp: empty argument not allowed");
                return;
            }

            if (isOption && (argVal.charAt(0) == '-')) {
                if (argVal.length() != 2) {
                    signalError(argv[0], "scp: only one option at a time may be specified");
                    return;
                }

                // TODO should we raise an error if option re-specified ?
                char optVal = argVal.charAt(1);
                switch (optVal) {
                    case 'r':
                        optR = true;
                        break;
                    case 't':
                        optT = true;
                        break;
                    case 'f':
                        optF = true;
                        break;
                    case 'd':
                        optD = true;
                        break;
                    case 'p':
                        optP = true;
                        break;
                    default:
                        signalError(argv[0], "scp: unsupported option: " + argVal);
                        return;
                }
            } else if (path == null) {
                path = argVal;
                isOption = false;
            } else {
                signalError(argv[0], "scp: one and only one path argument expected");
                return;
            }
        }

        if ((optT && optF) || (!optT && !optF)) {
            signalError(argv[0], "scp: one and only one of -t and -f option expected");
            return;
        }

        doScp(path, optR, optT, optF, optD, optP);
    }

    protected void doScp(
            String path, boolean optR, boolean optT, boolean optF, boolean optD, boolean optP)
            throws Exception {
        try {
            ScpHelper helper = new ScpHelper(
                    channel.getSession(), getInputStream(), getOutputStream(),
                    fileSystem, opener, listener);
            Path localPath = currentDir.resolve(path);
            if (optT) {
                helper.receive(localPath, optR, optD, optP, receiveBufferSize);
            } else {
                helper.send(Collections.singletonList(localPath.toString()), optR, optP, sendBufferSize);
            }
            variables.put(STATUS, 0);
        } catch (IOException e) {
            Integer statusCode = e instanceof ScpException ? ((ScpException) e).getExitStatus() : null;
            int exitValue = (statusCode == null) ? ScpAckInfo.ERROR : statusCode;
            // this is an exception so status cannot be OK/WARNING
            if ((exitValue == ScpAckInfo.OK) || (exitValue == ScpAckInfo.WARNING)) {
                exitValue = ScpAckInfo.ERROR;
            }
            String exitMessage = GenericUtils.trimToEmpty(e.getMessage());
            ScpAckInfo.sendAck(getOutputStream(), exitValue, exitMessage);
            variables.put(STATUS, exitValue);
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
        println(argv[0], buf, getOutputStream(), nameEncodingCharset);
        variables.put(STATUS, 0);
    }

    protected void pwd(String[] argv) throws Exception {
        if (argv.length != 1) {
            signalError(argv[0], "pwd: too many arguments");
        } else {
            println(argv[0], currentDir, getOutputStream(), nameEncodingCharset);
            variables.put(STATUS, 0);
        }
    }

    protected void cd(String[] argv) throws Exception {
        if (argv.length == 1) {
            if (homeDir != null) {
                currentDir = homeDir;
                updatePwdEnvVariable(currentDir);
                variables.put(STATUS, 0);
            } else {
                signalError(argv[0], "No home directory to return to");
            }

            return;
        }

        if (argv.length != 2) {
            signalError(argv[0], "cd: too many or too few arguments");
            return;
        }

        String path = argv[1];
        if (GenericUtils.isEmpty(path)) {
            signalError(argv[0], "cd: empty target");
            return;
        }

        // TODO make sure not escaping the user's sandbox filesystem
        Path cwd = currentDir;
        cwd = cwd.resolve(path).toAbsolutePath().normalize();
        if (!Files.exists(cwd)) {
            signalError(argv[0], "no such file or directory: " + path, nameEncodingCharset);
        } else if (!Files.isDirectory(cwd)) {
            signalError(argv[0], "not a directory: " + path, nameEncodingCharset);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("cd - {} => {}", currentDir, cwd);
            }
            currentDir = cwd;
            updatePwdEnvVariable(currentDir);
            variables.put(STATUS, 0);
        }
    }

    protected void updatePwdEnvVariable(Path pwd) {
        Environment environ = getEnvironment();
        Map<String, String> envVars = environ.getEnv();
        envVars.put(ENV_PWD, pwd.toString());
    }

    protected void ls(String[] argv) throws Exception {
        // find options
        boolean optListAll = false;
        boolean optDirAsPlain = false;
        boolean optLong = false;
        boolean optFullTime = false;
        String path = null;
        for (int k = 1; k < argv.length; k++) {
            String argValue = argv[k];
            if (GenericUtils.isEmpty(argValue)) {
                signalError(argv[0], "ls: empty argument not allowed");
                return;
            }

            if (argValue.equals("--full-time")) {
                optFullTime = true;
            } else if (argValue.charAt(0) == '-') {
                int argLen = argValue.length();
                if (argLen == 1) {
                    signalError(argv[0], "ls: no option specified");
                    return;
                }

                for (int i = 1; i < argLen; i++) {
                    char optValue = argValue.charAt(i);
                    // TODO should we raise an error if option re-specified ?
                    switch (optValue) {
                        case 'a':
                            optListAll = true;
                            break;
                        case 'd':
                            optDirAsPlain = true;
                            break;
                        case 'l':
                            optLong = true;
                            break;
                        default:
                            signalError(argv[0], "unsupported option: -" + optValue);
                            return;
                    }
                }
            } else if (path == null) {
                path = argValue;
            } else {
                signalError(argv[0], "unsupported option: " + argValue);
                return;
            }
        }

        doLs(argv[0], path, optListAll, optLong, optFullTime);
    }

    protected void doLs(
            String cmd, String path, boolean optListAll, boolean optLong, boolean optFullTime)
            throws Exception {
        // list current directory content
        Predicate<Path> filter = p -> {
            String fileName = p.getFileName().toString();
            return optListAll || fileName.equals(".")
                    || fileName.equals("..") || !fileName.startsWith(".");
        };

        // TODO make sure not listing above user's home directory
        Stream<Path> files = path != null
                ? Stream.of(currentDir.resolve(path))
                : Stream.concat(Stream.of(".", "..").map(currentDir::resolve), Files.list(currentDir));
        OutputStream stdout = getOutputStream();
        OutputStream stderr = getErrorStream();
        variables.put(STATUS, 0);
        files
                .filter(filter)
                .map(p -> new PathEntry(p, currentDir))
                .sorted()
                .forEach(p -> {
                    try {
                        String str = p.display(optLong, optFullTime);
                        println(cmd, str, stdout, nameEncodingCharset);
                    } catch (NoSuchFileException e) {
                        println(cmd, cmd + ": " + p.path.toString() + ": no such file or directory", stderr,
                                nameEncodingCharset);
                        variables.put(STATUS, 1);
                    }
                });
    }

    protected static class PathEntry implements Comparable<PathEntry> {
        public static final DateTimeFormatter FULL_TIME_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss yyyy");
        public static final DateTimeFormatter TIME_ONLY_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd HH:mm");
        public static final DateTimeFormatter YEAR_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd  yyyy");

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

        @Override
        public String toString() {
            return Objects.toString(abs);
        }

        public String display(boolean optLongDisplay, boolean optFullTime) throws NoSuchFileException {
            if (attributes.isEmpty()) {
                throw new NoSuchFileException(path.toString());
            }

            String abbrev = shortDisplay();
            if (!optLongDisplay) {
                return abbrev;
            }

            StringBuilder sb = new StringBuilder(abbrev.length() + 64);
            if (is("isDirectory")) {
                sb.append('d');
            } else if (is("isSymbolicLink")) {
                sb.append('l');
            } else if (is("isOther")) {
                sb.append('o');
            } else {
                sb.append('-');
            }

            @SuppressWarnings("unchecked")
            Set<PosixFilePermission> perms = (Set<PosixFilePermission>) attributes.get("permissions");
            if (perms == null) {
                perms = EnumSet.noneOf(PosixFilePermission.class);
            }
            sb.append(PosixFilePermissions.toString(perms));

            Object nlinkValue = attributes.get("nlink");
            sb.append(' ').append(String.format("%3s", (nlinkValue != null) ? nlinkValue : "1"));

            appendOwnerInformation(sb, "owner", "owner");
            appendOwnerInformation(sb, "group", "group");

            Number length = (Number) attributes.get("size");
            if (length == null) {
                length = 0L;
            }
            sb.append(' ').append(String.format("%1$8s", length));

            String timeValue = toString((FileTime) attributes.get("lastModifiedTime"), optFullTime);
            sb.append(' ').append(timeValue);

            sb.append(' ').append(abbrev);
            return sb.toString();
        }

        protected boolean is(String attr) {
            Object d = attributes.get(attr);
            return (d instanceof Boolean) && (Boolean) d;
        }

        protected StringBuilder appendOwnerInformation(
                StringBuilder sb, String attr, String defaultValue) {
            String owner = Objects.toString(attributes.get(attr), null);
            if (GenericUtils.isEmpty(owner)) {
                owner = defaultValue;
            }
            if (owner.length() > 8) {
                owner = owner.substring(0, 8);
            }
            sb.append(' ').append(owner);
            for (int index = owner.length(); index < 8; index++) {
                sb.append(' ');
            }
            return sb;
        }

        protected String shortDisplay() {
            if (is("isSymbolicLink")) {
                try {
                    Path l = Files.readSymbolicLink(abs);
                    return path + " -> " + l;
                } catch (IOException e) {
                    // ignore
                }
            }
            String str = path.toString();
            if (str.isEmpty()) {
                return abs.getFileName().toString();
            }
            return str;
        }

        protected static String toString(FileTime time, boolean optFullTime) {
            long millis = (time != null) ? time.toMillis() : -1L;
            if (millis < 0L) {
                return "------------";
            }

            ZonedDateTime dt = Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault());
            if (optFullTime) {
                return FULL_TIME_VALUE_FORMATTER.format(dt);
            } else if (System.currentTimeMillis() - millis < 183L * 24L * 60L * 60L * 1000L) {
                return TIME_ONLY_VALUE_FORMATTER.format(dt);
            } else {
                return YEAR_VALUE_FORMATTER.format(dt);
            }
        }

        protected static Map<String, Object> readAttributes(Path path) {
            Map<String, Object> attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            FileSystem fs = path.getFileSystem();
            Collection<String> views = fs.supportedFileAttributeViews();
            for (String view : views) {
                try {
                    Map<String, Object> ta = Files.readAttributes(
                            path, view + ":*", IoUtils.getLinkOptions(false));
                    ta.forEach(attrs::putIfAbsent);
                } catch (IOException e) {
                    // Ignore
                }
            }
            if (!attrs.isEmpty()) {
                attrs.computeIfAbsent("isExecutable", s -> Files.isExecutable(path));
                attrs.computeIfAbsent("permissions", s -> IoUtils.getPermissionsFromFile(path.toFile()));
            }
            return attrs;
        }
    }
}
