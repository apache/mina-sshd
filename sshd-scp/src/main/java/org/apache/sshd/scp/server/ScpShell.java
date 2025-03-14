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

import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStream;
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
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystem;
import org.apache.sshd.common.file.util.BaseFileSystem;
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
import org.apache.sshd.server.channel.ServerChannelSessionHolder;
import org.apache.sshd.server.command.AbstractFileSystemCommand;

/**
 * This command provides SCP support for a ChannelSession.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpShell extends AbstractFileSystemCommand implements ServerChannelSessionHolder {

    public static final String STATUS = "status";

    /** The "PWD" environment variable */
    public static final String ENV_PWD = "PWD";

    /** The "HOME" environment variable */
    public static final String ENV_HOME = "HOME";

    /**
     * Key for the language - format "en_US.UTF-8"
     */
    public static final String ENV_LANG = "LANG";

    private static final int LS_ALL = 1 << 0;
    private static final int LS_DIR_PLAIN = 1 << 1;
    private static final int LS_LONG = 1 << 2;
    private static final int LS_FULL_TIME = 1 << 3;

    private static final int SCP_D = 1 << 0;
    private static final int SCP_F = 1 << 1;
    private static final int SCP_P = 1 << 2;
    private static final int SCP_R = 1 << 3;
    private static final int SCP_T = 1 << 4;

    protected final Map<String, Object> variables = new HashMap<>();
    protected final Charset nameEncodingCharset;
    protected final Charset envVarsEnodingCharset;

    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;
    protected final int sendBufferSize;
    protected final int receiveBufferSize;
    protected Path currentDir;
    protected Path homeDir;

    private final ChannelSession channelSession;

    public ScpShell(ChannelSession channelSession, CloseableExecutorService executorService,
                    int sendSize, int receiveSize,
                    ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        super(null, executorService);
        this.channelSession = Objects.requireNonNull(channelSession, "No channel session provided");

        nameEncodingCharset = ScpModuleProperties.SHELL_NAME_ENCODING_CHARSET.getRequired(channelSession);
        envVarsEnodingCharset = ScpModuleProperties.SHELL_ENVVARS_ENCODING_CHARSET.getRequired(channelSession);

        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpShell> send buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }
        sendBufferSize = sendSize;

        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommmand> receive buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;

        opener = (fileOpener == null) ? DefaultScpFileOpener.INSTANCE : fileOpener;
        listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public ChannelSession getServerChannelSession() {
        return channelSession;
    }

    @Override
    public void setFileSystemFactory(FileSystemFactory factory, SessionContext session) throws IOException {
        homeDir = factory.getUserHomeDir(session);
        super.setFileSystemFactory(factory, session);
        FileSystem fs = getFileSystem();
        if (fs instanceof RootedFileSystem) {
            Path fsLocalRoot = ((RootedFileSystem) fs).getRoot();
            Path newHome = fs.getPath("/");
            if (homeDir != null && homeDir.startsWith(fsLocalRoot)) {
                homeDir = fsLocalRoot.relativize(homeDir);
                int n = homeDir.getNameCount();
                for (int i = 0; i < n; i++) {
                    Path p = homeDir.getName(i);
                    if (!p.toString().isEmpty()) {
                        newHome = newHome.resolve(p);
                    }
                }
            }
            homeDir = newHome;
            log.debug("Home dir in RootedFileSystem = {}", homeDir);
            currentDir = homeDir;
        } else if (fs instanceof BaseFileSystem<?>) {
            homeDir = ((BaseFileSystem<?>) fs).getDefaultDir();
            currentDir = homeDir;
        } else if (factory instanceof NativeFileSystemFactory) {
            // A native file system will allow the user to navigate anywhere. Not recommended.
            if (homeDir == null) {
                homeDir = new File(".").getCanonicalFile().toPath();
            }
            log.debug("Home dir in native FileSystem = {}", homeDir);
            currentDir = homeDir;
        } else {
            throw new IOException("ScpShell filesystem must be native or a RootedFileSystem or BaseFileSystem");
        }
    }

    protected void println(String cmd, Object x, OutputStream out, Charset cs) {
        try {
            String s = x.toString();
            if (log.isDebugEnabled()) {
                log.debug("println({})[{}]: {}",
                        getServerChannelSession(), cmd, s.replace('\n', ' ').replace('\t', ' '));
            }
            out.write(s.getBytes(cs));
            // always write LF even if running on Windows
            out.write('\n');
        } catch (IOException e) {
            throw new IOError(e);
        }
    }

    protected void signalError(String cmd, String errorMsg) {
        signalError(cmd, errorMsg, envVarsEnodingCharset);
    }

    protected void signalError(String cmd, String errorMsg, Charset cs) {
        log.warn("{}[{}]: {}", getServerChannelSession(), cmd, errorMsg);
        println(cmd, errorMsg, getErrorStream(), cs);
        variables.put(STATUS, 1);
    }

    @Override
    public void run() {
        String command = null;
        variables.put(STATUS, 0);

        boolean debugEnabled = log.isDebugEnabled();
        ChannelSession channel = getServerChannelSession();
        try {
            currentDir = homeDir;
            if (debugEnabled) {
                log.debug("run - starting at home dir={}", homeDir);
            }

            prepareEnvironment(getEnvironment());

            Charset decodingCharset = ScpModuleProperties.SHELL_NAME_DECODING_CHARSET.getRequired(channel);
            // Use a special stream reader so that the stream can be used with the scp command
            try (InputStream inputStream = getInputStream();
                 Reader r = new InputStreamReader(inputStream, decodingCharset)) {
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
                // Don't encode it with any user defined charset
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
            log.debug("handleCommandLine({}) {}", getServerChannelSession(), command);
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
                    scp(command, argv);
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
                    // Has no effect; we might also return status=0 (success)
                    variables.put(STATUS, 1);
                    break;
                default:
                    // TODO: rm -r -f path to support deletions
                    // TODO: mv -f oldname newname to support renaming
                    // TODO: mkdir name to create a new directory
                    // TODO: ln -s target link if the file system supports links
                    // TODO: chmod
                    // TODO: cp -p -r -f for remote-only copy
                    // see https://github.com/winscp/winscp/blob/88b50c1/source/core/ScpFileSystem.cpp#L108
                    // There'd be more, like sha512sum for supporting the checksum tab of file properties
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
        env.put(ENV_HOME, homeDir.toString());

        updatePwdEnvVariable(currentDir);
    }

    protected void handleUnsupportedCommand(String command, String[] argv) throws Exception {
        log.warn("handleUnsupportedCommand({}) unsupported: {}", getServerChannelSession(), command);
        variables.put(STATUS, 127);
        OutputStream errorStream = getErrorStream();
        // Don't encode it with any user defined charset
        errorStream.write(("command not found: " + argv[0] + "\n").getBytes(StandardCharsets.US_ASCII));
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
                    .forEach(e -> println(argv[0], e.getKey() + "=" + e.getValue(), stdout, envVarsEnodingCharset));
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
            log.debug("printenv({}) {}={}", getServerChannelSession(), varName, varValue);
        }

        println(argv[0], varValue, stdout, envVarsEnodingCharset);
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
            log.debug("unset({}) {}={}", getServerChannelSession(), varName, varValue);
        }
        variables.put(STATUS, (varValue == null) ? 1 : 0);
    }

    protected void scp(String command, String[] argv) throws Exception {
        int options = 0;
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
                        options |= SCP_R;
                        break;
                    case 't':
                        options |= SCP_T;
                        break;
                    case 'f':
                        options |= SCP_F;
                        break;
                    case 'd':
                        options |= SCP_D;
                        break;
                    case 'p':
                        options |= SCP_P;
                        break;
                    default:
                        signalError(argv[0], "scp: unsupported option: " + argVal);
                        return;
                }
            } else if (path == null) {
                // WinSCP sends local paths, but let's be sure here.
                path = toScpPath(argVal);
                isOption = false;
            } else {
                signalError(argv[0], "scp: one and only one path argument expected");
                return;
            }
        }

        int tf = options & (SCP_T | SCP_F);
        if (tf != SCP_T && tf != SCP_F) {
            signalError(argv[0], "scp: one and only one of -t and -f option expected");
            return;
        }

        doScp(command, path, options);
    }

    protected void doScp(String command, String path, int options) throws Exception {
        try {
            ChannelSession channel = getServerChannelSession();
            ScpHelper helper = new ScpHelper(
                    channel.getSession(), getInputStream(), getOutputStream(),
                    fileSystem, opener, listener);
            Path localPath = currentDir.resolve(path);
            if ((options & SCP_T) != 0) {
                if (log.isDebugEnabled()) {
                    log.debug("doScp({}) receiving file in {} at {}", getServerChannelSession(), path, localPath);
                }
                helper.receive(command, localPath, (options & SCP_R) != 0, (options & SCP_D) != 0, (options & SCP_P) != 0,
                        receiveBufferSize);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("doScp({}) sending file {} from {}", getServerChannelSession(), path, localPath);
                }
                helper.send(Collections.singletonList(localPath.toString()), (options & SCP_R) != 0, (options & SCP_P) != 0,
                        sendBufferSize);
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
            ScpAckInfo.sendAck(getOutputStream(), StandardCharsets.UTF_8, exitValue, exitMessage);
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

    private String toScpPath(String winScpPath) {
        // WinSCP may send windows paths like C:\foo\bar. Map this to a virtual path if needed.
        String separator = fileSystem.getSeparator();
        String scpPath = winScpPath.replace("\\", separator);
        if (scpPath.equals(winScpPath)) {
            // Assume it's OK
            return scpPath;
        }
        int i = scpPath.indexOf(separator);
        // TODO: UNC paths? Funny \? prefixes? Looks like WinSCP doesn't send those.
        if (i == 2 && scpPath.charAt(1) == ':') {
            // Strip drive letter
            scpPath = scpPath.substring(2);
        }
        return scpPath;
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
        cwd = cwd.resolve(toScpPath(path)).toAbsolutePath().normalize();
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
        int options = 0;
        String path = null;
        for (int k = 1; k < argv.length; k++) {
            String argValue = argv[k];
            if (GenericUtils.isEmpty(argValue)) {
                signalError(argv[0], "ls: empty argument not allowed");
                return;
            }

            if (argValue.equals("--full-time")) {
                options |= LS_FULL_TIME;
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
                            options |= LS_ALL;
                            break;
                        case 'd':
                            options |= LS_DIR_PLAIN;
                            break;
                        case 'l':
                            options |= LS_LONG;
                            break;
                        default:
                            signalError(argv[0], "unsupported option: -" + optValue);
                            return;
                    }
                }
            } else if (path == null) {
                path = toScpPath(argValue);
            } else {
                signalError(argv[0], "unsupported option: " + argValue);
                return;
            }
        }

        doLs(argv[0], path, options);
    }

    protected void doLs(String cmd, String path, int options) throws Exception {
        boolean listDirectory = path == null;
        Path toList = currentDir;
        if (path != null) {
            toList = currentDir.resolve(path);
            listDirectory = ((options & LS_DIR_PLAIN) == 0) && Files.isDirectory(toList);
        }
        Path inDir = listDirectory ? toList : currentDir;
        // Hide the .. entry if we're listing the root
        Stream<String> dotDirs = Stream.empty();
        if (listDirectory) {
            dotDirs = toList.getNameCount() == 0 ? Stream.of(".") : Stream.of(".", "..");
        }
        Predicate<Path> filter;
        if (!listDirectory || (options & LS_ALL) != 0) {
            filter = p -> true;
        } else {
            filter = p -> {
                String fileName = p.getFileName().toString();
                return fileName.equals(".") || fileName.equals("..") || !fileName.startsWith(".");
            };
        }
        try (Stream<Path> files = !listDirectory
                ? Stream.of(toList)
                : Stream.concat(dotDirs.map(toList::resolve), Files.list(toList))) {
            OutputStream stdout = getOutputStream();
            OutputStream stderr = getErrorStream();
            variables.put(STATUS, 0);
            files
                    .filter(filter)
                    .map(p -> new PathEntry(p, inDir))
                    .sorted()
                    .forEach(p -> {
                        try {
                            String str = p.display((options & LS_LONG) != 0, (options & LS_FULL_TIME) != 0);
                            println(cmd, str, stdout, nameEncodingCharset);
                        } catch (NoSuchFileException e) {
                            println(cmd, cmd + ": " + p.path.toString() + ": no such file or directory", stderr,
                                    nameEncodingCharset);
                            variables.put(STATUS, 1);
                        }
                    });
        }
    }

    protected static class PathEntry implements Comparable<PathEntry> {
        // WinSCP needs the month names always in English.
        public static final DateTimeFormatter FULL_TIME_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss yyyy",
                Locale.ENGLISH);
        public static final DateTimeFormatter TIME_ONLY_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd HH:mm",
                Locale.ENGLISH);
        public static final DateTimeFormatter YEAR_VALUE_FORMATTER = DateTimeFormatter.ofPattern("MMM ppd  yyyy",
                Locale.ENGLISH);

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
            if (is(IoUtils.DIRECTORY_VIEW_ATTR)) {
                sb.append('d');
            } else if (is(IoUtils.SYMLINK_VIEW_ATTR)) {
                sb.append('l');
            } else if (is(IoUtils.OTHERFILE_VIEW_ATTR)) {
                sb.append('o');
            } else {
                sb.append('-');
            }

            @SuppressWarnings("unchecked")
            Set<PosixFilePermission> perms = (Set<PosixFilePermission>) attributes.get(IoUtils.PERMISSIONS_VIEW_ATTR);
            if (perms == null) {
                perms = EnumSet.noneOf(PosixFilePermission.class);
            }
            sb.append(PosixFilePermissions.toString(perms));

            Object nlinkValue = attributes.get(IoUtils.NUMLINKS_VIEW_ATTR);
            sb.append(' ').append(String.format("%3s", (nlinkValue != null) ? nlinkValue : "1"));

            appendOwnerInformation(sb, IoUtils.OWNER_VIEW_ATTR, "owner");
            appendOwnerInformation(sb, IoUtils.GROUP_VIEW_ATTR, "group");

            Number length = (Number) attributes.get(IoUtils.SIZE_VIEW_ATTR);
            if (length == null) {
                length = 0L;
            }
            sb.append(' ').append(String.format("%1$8s", length));

            String timeValue = toString((FileTime) attributes.get(IoUtils.LASTMOD_TIME_VIEW_ATTR), optFullTime);
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
                attrs.computeIfAbsent(IoUtils.EXECUTABLE_VIEW_ATTR, s -> Files.isExecutable(path));
                attrs.computeIfAbsent(IoUtils.PERMISSIONS_VIEW_ATTR, s -> IoUtils.getPermissionsFromFile(path.toFile()));
            }
            return attrs;
        }
    }
}
