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

package org.apache.sshd.cli.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.channels.Channel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.apache.sshd.cli.CliLogger;
import org.apache.sshd.cli.client.helper.SftpFileTransferProgressOutputStream;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.MacFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.config.SshServerConfigFileReader;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.client.SftpVersionSelector.NamedVersionSelector;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatExtensionInfo;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatPathExtension;
import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.extensions.ParserUtils;
import org.apache.sshd.sftp.common.extensions.openssh.StatVfsExtensionParser;
import org.slf4j.Logger;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpCommandMain extends SshClientCliSupport implements Channel {
    /**
     * Command line option used to indicate a non-default port number
     */
    public static final String SFTP_PORT_OPTION = "-P";

    private final SftpClient client;
    private final Map<String, SftpCommandExecutor> commandsMap;
    private String cwdRemote;
    private String cwdLocal;
    private boolean showProgress = true;

    public SftpCommandMain(SftpClient client) {
        this.client = Objects.requireNonNull(client, "No client");

        Map<String, SftpCommandExecutor> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (SftpCommandExecutor e : Arrays.asList(
                new ExitCommandExecutor(),
                new PwdCommandExecutor(),
                new InfoCommandExecutor(),
                new SessionCommandExecutor(),
                new KexCommandExecutor(),
                new ClientCommandExecutor(),
                new VersionCommandExecutor(),
                new CdCommandExecutor(),
                new LcdCommandExecutor(),
                new MkdirCommandExecutor(),
                new LsCommandExecutor(),
                new LStatCommandExecutor(),
                new ReadLinkCommandExecutor(),
                new RmCommandExecutor(),
                new RmdirCommandExecutor(),
                new RenameCommandExecutor(),
                new StatVfsCommandExecutor(),
                new GetCommandExecutor(),
                new PutCommandExecutor(),
                new ProgressCommandExecutor(),
                new HelpCommandExecutor())) {
            String name = e.getName();
            ValidateUtils.checkTrue(map.put(name, e) == null, "Multiple commands named '%s'", name);
        }
        commandsMap = Collections.unmodifiableMap(map);
        cwdLocal = System.getProperty("user.dir");
    }

    public final SftpClient getClient() {
        return client;
    }

    public void doInteractive(BufferedReader stdin, PrintStream stdout, PrintStream stderr) throws Exception {
        SftpClient sftp = getClient();
        setCurrentRemoteDirectory(sftp.canonicalPath("."));
        while (true) {
            stdout.append(getCurrentRemoteDirectory()).append(" > ").flush();
            String line = stdin.readLine();
            if (line == null) { // EOF
                break;
            }

            line = GenericUtils.replaceWhitespaceAndTrim(line);
            if (GenericUtils.isEmpty(line)) {
                continue;
            }

            String cmd;
            String args;
            int pos = line.indexOf(' ');
            if (pos > 0) {
                cmd = line.substring(0, pos);
                args = line.substring(pos + 1).trim();
            } else {
                cmd = line;
                args = "";
            }

            SftpCommandExecutor exec = commandsMap.get(cmd);
            try {
                if (exec == null) {
                    stderr.append("Unknown command: ").println(line);
                } else {
                    try {
                        if (exec.executeCommand(args, stdin, stdout, stderr)) {
                            break;
                        }
                    } catch (Exception e) {
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

    protected String resolveLocalPath(String pathArg) {
        String cwd = getCurrentLocalDirectory();
        if (GenericUtils.isEmpty(pathArg)) {
            return cwd;
        }

        if (OsUtils.isWin32()) {
            if ((pathArg.length() >= 2) && (pathArg.charAt(1) == ':')) {
                return pathArg;
            }
        } else {
            if (pathArg.charAt(0) == '/') {
                return pathArg;
            }
        }

        return cwd + File.separator + pathArg.replace('/', File.separatorChar);
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

    protected <A extends Appendable> A appendFileAttributes(
            A stdout, SftpClient sftp, String path, Attributes attrs)
            throws IOException {
        stdout.append("    ").append(Long.toString(attrs.getSize()))
                .append("    ").append(SftpFileSystemProvider.getRWXPermissions(attrs.getPermissions()));
        if (attrs.isSymbolicLink()) {
            String linkValue = sftp.readLink(path);
            stdout.append(" => ")
                    .append('(').append(attrs.isDirectory() ? "dir" : "file").append(')')
                    .append(' ').append(linkValue);
        }

        return stdout;
    }

    public String getCurrentRemoteDirectory() {
        return cwdRemote;
    }

    public void setCurrentRemoteDirectory(String path) {
        cwdRemote = path;
    }

    public String getCurrentLocalDirectory() {
        return cwdLocal;
    }

    public void setCurrentLocalDirectory(String path) {
        cwdLocal = path;
    }

    public boolean isShowProgress() {
        return showProgress;
    }

    public void setShowProgress(boolean showProgress) {
        this.showProgress = showProgress;
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

    //////////////////////////////////////////////////////////////////////////

    public static <A extends Appendable> A appendInfoValue(A sb, CharSequence name, Object value) throws IOException {
        sb.append("    ").append(name).append(": ").append(Objects.toString(value));
        return sb;
    }

    /* -------------------------------------------------------------------- */

    public static SftpClientFactory resolveSftpClientFactory(ClientSession session) {
        ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(SftpClientFactory.class);
        String factoryName = session.getString(SftpClientFactory.class.getSimpleName());
        if (GenericUtils.isNotEmpty(factoryName)) {
            try {
                Class<?> clazz = cl.loadClass(factoryName);
                return ReflectionUtils.newInstance(clazz, SftpClientFactory.class);
            } catch (Throwable t) {
                System.err.append("Failed (").append(t.getClass().getSimpleName()).append(')')
                        .append(" to instantiate ").append(factoryName)
                        .append(": ").println(t.getMessage());
                System.err.flush();
                throw GenericUtils.toRuntimeException(t, true);
            }
        }

        ServiceLoader<SftpClientFactory> loader = ServiceLoader.load(SftpClientFactory.class, cl);
        SftpClientFactory factory = null;
        for (SftpClientFactory f : loader) {
            ValidateUtils.checkState(factory == null, "Multiple factories detected - select one");
            factory = f;
        }

        if (factory != null) {
            return factory;
        }

        return SftpClientFactory.instance();
    }

    /* -------------------------------------------------------------------- */

    public static NamedVersionSelector resolveVersionSelector(ClientSession session) {
        String selector = session.getString(SshServerConfigFileReader.SFTP_FORCED_VERSION_PROP.getName());
        return SftpVersionSelector.resolveVersionSelector(selector);
    }

    /* -------------------------------------------------------------------- */

    public static void main(String[] args) throws Exception {
        PrintStream stdout = System.out;
        PrintStream stderr = System.err;
        OutputStream logStream = stderr;
        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(new NoCloseInputStream(System.in)))) {
            Level level = CliLogger.resolveLoggingVerbosity(args);
            logStream = resolveLoggingTargetStream(stdout, stderr, args);
            if (logStream != null) {
                setupLogging(level, stdout, stderr, logStream);
            }

            ClientSession session = (logStream == null)
                    ? null
                    : setupClientSession(SFTP_PORT_OPTION, stdin, level, stdout, stderr, args);
            if (session == null) {
                System.err.println("usage: sftp [-v[v][v]] [-E logoutput] [-i identity] [-io nio2|mina|netty]"
                                   + " [-J proxyJump] [-l login] [" + SFTP_PORT_OPTION + " port] [-o option=value]"
                                   + " [-w password] [-c cipherlist] [-m maclist] [-C] hostname/user@host");
                System.exit(-1);
                return;
            }

            try {
                SftpClientFactory clientFactory = resolveSftpClientFactory(session);
                Logger logger = (logStream != null)
                        ? CliLogger.getLogger(SftpCommandMain.class, level,
                                (logStream instanceof PrintStream) ? (PrintStream) logStream : new PrintStream(logStream))
                        : CliLogger.resolveSystemLogger(SftpCommandMain.class, level);
                if (logger.isInfoEnabled()) {
                    logger.info("Using factory={}", clientFactory.getClass().getSimpleName());
                }

                SftpVersionSelector versionSelector = resolveVersionSelector(session);
                if (logger.isInfoEnabled()) {
                    logger.info("Using version selector={}", versionSelector);
                }

                try (SftpClient sftpClient = clientFactory.createSftpClient(session, versionSelector);
                     SftpCommandMain sftp = new SftpCommandMain(sftpClient)) {
                    // TODO allow injection of extra CommandExecutor(s) via command line and/or service loading
                    sftp.doInteractive(stdin, stdout, stderr);
                }
            } finally {
                session.close();
            }
        } finally {
            if ((logStream != stdout) && (logStream != stderr)) {
                logStream.close();
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////

    private static class ExitCommandExecutor implements SftpCommandExecutor {
        ExitCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "exit";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            stdout.println("Exiting");
            return true;
        }
    }

    /* -------------------------------------------------------------------- */

    private class PwdCommandExecutor implements SftpCommandExecutor {
        protected PwdCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "pwd";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            stdout.append("    ").append("Remote: ").println(getCurrentRemoteDirectory());
            stdout.append("    ").append("Local: ").println(getCurrentLocalDirectory());
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class SessionCommandExecutor implements SftpCommandExecutor {
        SessionCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "session";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            SftpClient sftp = getClient();
            ClientSession session = sftp.getSession();
            appendInfoValue(stdout, "Session ID", BufferUtils.toHex(session.getSessionId())).println();
            appendInfoValue(stdout, "Connect address", session.getConnectAddress()).println();

            IoSession ioSession = session.getIoSession();
            appendInfoValue(stdout, "Local address", ioSession.getLocalAddress()).println();
            appendInfoValue(stdout, "Remote address", ioSession.getRemoteAddress()).println();

            appendInfoValue(stdout, "Client version", session.getClientVersion()).println();
            appendInfoValue(stdout, "Server version", session.getServerVersion()).println();
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class KexCommandExecutor implements SftpCommandExecutor {
        KexCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "kex";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            SftpClient sftp = getClient();
            ClientSession session = sftp.getSession();

            Map<KexProposalOption, String> clientProposals = session.getClientKexProposals();
            Map<KexProposalOption, String> serverProposals = session.getServerKexProposals();
            Map<KexProposalOption, String> negotiated = session.getKexNegotiationResult();
            for (KexProposalOption option : KexProposalOption.VALUES) {
                String description = option.getDescription();
                appendInfoValue(stdout, description + "[client]", clientProposals.get(option)).println();
                appendInfoValue(stdout, description + "[server]", serverProposals.get(option)).println();
                appendInfoValue(stdout, description + "[negotiated]", negotiated.get(option)).println();
            }

            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class ClientCommandExecutor implements SftpCommandExecutor {
        ClientCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "client";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            SftpClient sftp = getClient();
            ClientSession session = sftp.getSession();
            ClientFactoryManager manager = session.getFactoryManager();
            appendInfoValue(stdout, IoServiceFactory.class.getSimpleName(),
                    manager.getIoServiceFactory().getClass().getSimpleName()).println();
            appendInfoValue(stdout, CipherFactory.class.getSimpleName(), NamedResource.getNames(manager.getCipherFactories()))
                    .println();
            appendInfoValue(stdout, KeyExchange.class.getSimpleName(),
                    NamedResource.getNames(manager.getKeyExchangeFactories())).println();
            appendInfoValue(stdout, SignatureFactory.class.getSimpleName(),
                    NamedResource.getNames(manager.getSignatureFactories())).println();
            appendInfoValue(stdout, MacFactory.class.getSimpleName(), NamedResource.getNames(manager.getMacFactories()))
                    .println();
            appendInfoValue(stdout, CompressionFactory.class.getSimpleName(),
                    NamedResource.getNames(manager.getCompressionFactories())).println();
            appendInfoValue(stdout, ChannelFactory.class.getSimpleName(), NamedResource.getNames(manager.getChannelFactories()))
                    .println();
            appendInfoValue(stdout, ServiceFactory.class.getSimpleName(), NamedResource.getNames(manager.getServiceFactories()))
                    .println();
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class InfoCommandExecutor implements SftpCommandExecutor {
        InfoCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "info";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            SftpClient sftp = getClient();
            Session session = sftp.getSession();
            stdout.append("    ").println(session.getServerVersion());

            Map<String, byte[]> extensions = sftp.getServerExtensions();
            Map<String, ?> parsed = ParserUtils.parse(extensions);
            if (GenericUtils.size(extensions) > 0) {
                stdout.println();
            }

            extensions.forEach((name, value) -> {
                Object info = parsed.get(name);

                stdout.append("    ").append(name).append(": ");
                if (info == null) {
                    stdout.println(BufferUtils.toHex(value));
                } else {
                    stdout.println(info);
                }
            });

            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class VersionCommandExecutor implements SftpCommandExecutor {
        VersionCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "version";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            SftpClient sftp = getClient();
            stdout.append("    ").println(sftp.getVersion());
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class CdCommandExecutor extends PwdCommandExecutor {
        CdCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "cd";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified");

            String newPath = resolveRemotePath(args);
            SftpClient sftp = getClient();
            setCurrentRemoteDirectory(sftp.canonicalPath(newPath));
            return super.executeCommand("", stdin, stdout, stderr);
        }
    }

    /* -------------------------------------------------------------------- */

    private class LcdCommandExecutor extends PwdCommandExecutor {
        LcdCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "lcd";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            if (GenericUtils.isEmpty(args)) {
                setCurrentLocalDirectory(System.getProperty("user.home"));
            } else {
                Path path = Paths.get(resolveLocalPath(args)).normalize().toAbsolutePath();
                ValidateUtils.checkTrue(Files.exists(path), "No such local directory: %s", path);
                ValidateUtils.checkTrue(Files.isDirectory(path), "Path is not a directory: %s", path);
                setCurrentLocalDirectory(path.toString());
            }

            return super.executeCommand("", stdin, stdout, stderr);
        }
    }

    /* -------------------------------------------------------------------- */

    private class MkdirCommandExecutor implements SftpCommandExecutor {
        MkdirCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "mkdir";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified");

            String path = resolveRemotePath(args);
            SftpClient sftp = getClient();
            sftp.mkdir(path);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class LsCommandExecutor implements SftpCommandExecutor {
        LsCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "ls";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            int numComps = GenericUtils.length(comps);
            String pathArg = (numComps <= 0) ? null : GenericUtils.trimToEmpty(comps[numComps - 1]);
            String flags = (numComps >= 2) ? GenericUtils.trimToEmpty(comps[0]) : null;
            // ignore all flags
            if ((GenericUtils.length(pathArg) > 0) && (pathArg.charAt(0) == '-')) {
                flags = pathArg;
                pathArg = null;
            }

            String path = resolveRemotePath(pathArg);
            SftpClient sftp = getClient();
            int version = sftp.getVersion();
            boolean showLongName
                    = (version == SftpConstants.SFTP_V3) && (GenericUtils.length(flags) > 1) && (flags.indexOf('l') > 0);
            for (SftpClient.DirEntry entry : sftp.readDir(path)) {
                String fileName = entry.getFilename();
                SftpClient.Attributes attrs = entry.getAttributes();
                appendFileAttributes(stdout.append("    ").append(fileName), sftp, path + "/" + fileName, attrs).println();
                if (showLongName) {
                    stdout.append("\t\tlong-name: ").println(entry.getLongFilename());
                }
            }

            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class RmCommandExecutor implements SftpCommandExecutor {
        RmCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "rm";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            int numArgs = GenericUtils.length(comps);
            ValidateUtils.checkTrue(numArgs >= 1, "No arguments");
            ValidateUtils.checkTrue(numArgs <= 2, "Too many arguments: %s", args);

            String remotePath = comps[0];
            boolean recursive = false;
            boolean verbose = false;
            if (remotePath.charAt(0) == '-') {
                ValidateUtils.checkTrue(remotePath.length() > 1, "Missing flags specification: %s", args);
                ValidateUtils.checkTrue(numArgs == 2, "Missing remote directory: %s", args);

                for (int index = 1; index < remotePath.length(); index++) {
                    char ch = remotePath.charAt(index);
                    switch (ch) {
                        case 'r':
                            recursive = true;
                            break;
                        case 'v':
                            verbose = true;
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown flag (" + Character.toString(ch) + ")");
                    }
                }
                remotePath = comps[1];
            }

            String path = resolveRemotePath(remotePath);
            SftpClient sftp = getClient();
            if (recursive) {
                Attributes attrs = sftp.stat(path);
                ValidateUtils.checkTrue(attrs.isDirectory(), "Remote path not a directory: %s", args);
                removeRecursive(sftp, path, attrs, stdout, verbose);
            } else {
                sftp.remove(path);
                if (verbose) {
                    stdout.append("    ").append("Removed ").println(path);
                }
            }

            return false;
        }

        private void removeRecursive(
                SftpClient sftp, String path, Attributes attrs, PrintStream stdout, boolean verbose)
                throws IOException {
            if (attrs.isDirectory()) {
                for (DirEntry entry : sftp.readDir(path)) {
                    String name = entry.getFilename();
                    if (".".equals(name) || "..".equals(name)) {
                        continue;
                    }

                    removeRecursive(sftp, path + "/" + name, entry.getAttributes(), stdout, verbose);
                }

                sftp.rmdir(path);
            } else if (attrs.isRegularFile()) {
                sftp.remove(path);
            } else {
                if (verbose) {
                    stdout.append("    ").append("Skip special file ").println(path);
                    return;
                }
            }

            if (verbose) {
                stdout.append("    ").append("Removed ").println(path);
            }
        }
    }

    /* -------------------------------------------------------------------- */

    private class RmdirCommandExecutor implements SftpCommandExecutor {
        RmdirCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "rmdir";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkNotNullAndNotEmpty(args, "No remote directory specified");

            String path = resolveRemotePath(args);
            SftpClient sftp = getClient();
            sftp.rmdir(path);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class RenameCommandExecutor implements SftpCommandExecutor {
        RenameCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "rename";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            ValidateUtils.checkTrue(GenericUtils.length(comps) == 2, "Invalid number of arguments: %s", args);

            String oldPath = resolveRemotePath(GenericUtils.trimToEmpty(comps[0]));
            String newPath = resolveRemotePath(GenericUtils.trimToEmpty(comps[1]));
            SftpClient sftp = getClient();
            sftp.rename(oldPath, newPath);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class StatVfsCommandExecutor implements SftpCommandExecutor {
        StatVfsCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return StatVfsExtensionParser.NAME;
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            int numArgs = GenericUtils.length(comps);
            ValidateUtils.checkTrue(numArgs <= 1, "Invalid number of arguments: %s", args);

            SftpClient sftp = getClient();
            OpenSSHStatPathExtension ext = sftp.getExtension(OpenSSHStatPathExtension.class);
            ValidateUtils.checkTrue(ext.isSupported(), "Extension not supported by server: %s", ext.getName());

            String remPath = resolveRemotePath(
                    (numArgs >= 1) ? GenericUtils.trimToEmpty(comps[0]) : GenericUtils.trimToEmpty(args));
            OpenSSHStatExtensionInfo info = ext.stat(remPath);
            Field[] fields = info.getClass().getFields();
            for (Field f : fields) {
                String name = f.getName();
                int mod = f.getModifiers();
                if (Modifier.isStatic(mod)) {
                    continue;
                }

                Object value = f.get(info);
                stdout.append("    ").append(name).append(": ").println(value);
            }

            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class LStatCommandExecutor implements SftpCommandExecutor {
        LStatCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "lstat";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            ValidateUtils.checkTrue(GenericUtils.length(comps) <= 1, "Invalid number of arguments: %s", args);

            String path = GenericUtils.trimToEmpty(resolveRemotePath(args));
            SftpClient client = getClient();
            Attributes attrs = client.lstat(path);
            appendFileAttributes(stdout, client, path, attrs).println();
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class ReadLinkCommandExecutor implements SftpCommandExecutor {
        ReadLinkCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "readlink";
        }

        @Override
        public boolean executeCommand(String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            ValidateUtils.checkTrue(GenericUtils.length(comps) <= 1, "Invalid number of arguments: %s", args);

            String path = GenericUtils.trimToEmpty(resolveRemotePath(args));
            SftpClient client = getClient();
            String linkData = client.readLink(path);
            stdout.append("    ").println(linkData);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class HelpCommandExecutor implements SftpCommandExecutor {
        HelpCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "help";
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            ValidateUtils.checkTrue(GenericUtils.isEmpty(args), "Unexpected arguments: %s", args);
            for (String cmd : commandsMap.keySet()) {
                stdout.append("    ").println(cmd);
            }
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private abstract class TransferCommandExecutor implements SftpCommandExecutor {
        protected TransferCommandExecutor() {
            super();
        }

        protected void createDirectories(
                SftpClient sftp, String remotePath, PrintStream stdout, boolean verbose)
                throws IOException {
            try {
                Attributes attrs = sftp.stat(remotePath);
                ValidateUtils.checkTrue(attrs.isDirectory(), "Remote path already exists but is not a directory: %s",
                        remotePath);
                return;
            } catch (SftpException e) {
                int status = e.getStatus();
                ValidateUtils.checkTrue(status == SftpConstants.SSH_FX_NO_SUCH_FILE, "Failed to get status of %s: %s",
                        remotePath, e.getMessage());
            }

            int pos = remotePath.lastIndexOf('/');
            ValidateUtils.checkTrue(pos > 0, "No more parents for %s", remotePath);
            createDirectories(sftp, remotePath.substring(0, pos), stdout, verbose);
        }

        protected void transferFile(
                SftpClient sftp, Path localPath, String remotePath, boolean upload, PrintStream stdout, boolean verbose)
                throws IOException {
            // Create the file's hierarchy
            if (upload) {
                int pos = remotePath.lastIndexOf('/');
                ValidateUtils.checkTrue(pos > 0, "Missing full remote file path: %s", remotePath);
                createDirectories(sftp, remotePath.substring(0, pos), stdout, verbose);

                if (verbose) {
                    stdout.append("    Uploading ").append(Long.toString(Files.size(localPath)))
                            .append(" bytes from ").append(localPath.toString())
                            .append(" to ").println(remotePath);
                }
            } else {
                Files.createDirectories(localPath.getParent());

                if (verbose) {
                    Attributes attrs = sftp.stat(remotePath);
                    stdout.append("    Downloading ").append(Long.toString(attrs.getSize()))
                            .append(" bytes from ").append(remotePath)
                            .append(" to ").println(localPath);
                }
            }

            boolean withProgress = isShowProgress();
            long copySize;
            long startTime = System.currentTimeMillis();
            try (InputStream input = upload ? Files.newInputStream(localPath) : sftp.read(remotePath);
                 OutputStream target = upload ? sftp.write(remotePath) : Files.newOutputStream(localPath);
                 OutputStream output = withProgress ? new SftpFileTransferProgressOutputStream(target, stdout) : target) {
                if (withProgress) {
                    stdout.println();
                }

                copySize = IoUtils.copy(input, output, SftpClient.IO_BUFFER_SIZE);

                if (withProgress) {
                    stdout.println();
                }
            }

            if (verbose) {
                stdout.append("    Copied ").append(Long.toString(copySize)).append(" bytes")
                        .append(" in ")
                        .append(Long.toString(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - startTime)))
                        .append(" seconds from ").append(upload ? localPath.toString() : remotePath)
                        .append(" to ").println(upload ? remotePath : localPath.toString());
            }
        }

        protected void transferRemoteDir(
                SftpClient sftp, Path localPath, String remotePath, Attributes attrs, PrintStream stdout, boolean verbose)
                throws IOException {
            if (attrs.isDirectory()) {
                for (DirEntry entry : sftp.readDir(remotePath)) {
                    String name = entry.getFilename();
                    if (".".equals(name) || "..".equals(name)) {
                        continue;
                    }

                    transferRemoteDir(sftp, localPath.resolve(name), remotePath + "/" + name, entry.getAttributes(), stdout,
                            verbose);
                }
            } else if (attrs.isRegularFile()) {
                transferFile(sftp, localPath, remotePath, false, stdout, verbose);
            } else {
                if (verbose) {
                    stdout.append("    ").append("Skip remote special file ").println(remotePath);
                }
            }
        }

        protected void transferLocalDir(
                SftpClient sftp, Path localPath, String remotePath, PrintStream stdout, boolean verbose)
                throws IOException {
            if (Files.isDirectory(localPath)) {
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(localPath)) {
                    for (Path entry : ds) {
                        Path fileName = entry.getFileName();
                        String name = fileName.toString();
                        transferLocalDir(sftp, localPath.resolve(name), remotePath + "/" + name, stdout, verbose);
                    }
                }
            } else if (Files.isRegularFile(localPath)) {
                transferFile(sftp, localPath, remotePath, true, stdout, verbose);
            } else {
                if (verbose) {
                    stdout.append("    ").append("Skip local special file ").println(localPath);
                }
            }
        }

        protected void executeCommand(String args, boolean upload, PrintStream stdout) throws IOException {
            String[] comps = GenericUtils.split(args, ' ');
            int numArgs = GenericUtils.length(comps);
            ValidateUtils.checkTrue((numArgs >= 1) && (numArgs <= 3), "Invalid number of arguments: %s", args);

            String src = comps[0];
            boolean recursive = false;
            boolean verbose = false;
            int tgtIndex = 1;
            if (src.charAt(0) == '-') {
                ValidateUtils.checkTrue(src.length() > 1, "Missing flags specification: %s", args);
                ValidateUtils.checkTrue(numArgs >= 2, "Missing source specification: %s", args);

                for (int index = 1; index < src.length(); index++) {
                    char ch = src.charAt(index);
                    switch (ch) {
                        case 'r':
                            recursive = true;
                            break;
                        case 'v':
                            verbose = true;
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown flag (" + Character.toString(ch) + ")");
                    }
                }
                src = comps[1];
                tgtIndex++;
            }

            String tgt = (tgtIndex < numArgs) ? comps[tgtIndex] : null;
            String localPath;
            String remotePath;
            if (upload) {
                localPath = src;
                remotePath = ValidateUtils.checkNotNullAndNotEmpty(tgt, "No remote target specified: %s", args);
            } else {
                localPath = GenericUtils.isEmpty(tgt) ? getCurrentLocalDirectory() : tgt;
                remotePath = src;
            }

            SftpClient sftp = getClient();
            Path local = Paths.get(resolveLocalPath(localPath)).normalize().toAbsolutePath();
            String remote = resolveRemotePath(remotePath);
            if (recursive) {
                if (upload) {
                    ValidateUtils.checkTrue(Files.isDirectory(local), "Local path not a directory or does not exist: %s",
                            local);
                    transferLocalDir(sftp, local, remote, stdout, verbose);
                } else {
                    Attributes attrs = sftp.stat(remote);
                    ValidateUtils.checkTrue(attrs.isDirectory(), "Remote path not a directory: %s", remote);
                    transferRemoteDir(sftp, local, remote, attrs, stdout, verbose);
                }
            } else {
                if (Files.exists(local) && Files.isDirectory(local)) {
                    int pos = remote.lastIndexOf('/');
                    String name = (pos >= 0) ? remote.substring(pos + 1) : remote;
                    local = local.resolve(name);
                }

                transferFile(sftp, local, remote, upload, stdout, verbose);
            }
        }
    }

    /* -------------------------------------------------------------------- */

    private class GetCommandExecutor extends TransferCommandExecutor {
        GetCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "get";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            executeCommand(args, false, stdout);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class PutCommandExecutor extends TransferCommandExecutor {
        PutCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "put";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            executeCommand(args, true, stdout);
            return false;
        }
    }

    /* -------------------------------------------------------------------- */

    private class ProgressCommandExecutor implements SftpCommandExecutor {
        ProgressCommandExecutor() {
            super();
        }

        @Override
        public String getName() {
            return "progress";
        }

        @Override
        public boolean executeCommand(
                String args, BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Exception {
            String[] comps = GenericUtils.split(args, ' ');
            int numArgs = GenericUtils.length(comps);
            if (numArgs <= 0) {
                stdout.append("    ").append(getName()).append(' ').println(isShowProgress() ? "on" : "off");
            } else {
                ValidateUtils.checkTrue(numArgs == 1, "Invalid arguments count: %d", numArgs);

                String argVal = comps[0];
                if ("on".equalsIgnoreCase(argVal)) {
                    setShowProgress(true);
                } else if ("off".equalsIgnoreCase(argVal)) {
                    setShowProgress(false);
                } else {
                    throw new IllegalArgumentException("Unknown value: " + argVal);
                }
            }

            return false;
        }
    }
}
