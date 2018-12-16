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
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.client.ClientAuthenticationManager;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.config.keys.ClientIdentity;
import org.apache.sshd.client.keyverifier.DefaultKnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.config.CompressionConfigValue;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.NoCloseOutputStream;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SshClientCliSupport extends CliSupport {
    /**
     * Command line option used to indicate non-default target port
     */
    public static final String SSH_CLIENT_PORT_OPTION = "-p";

    protected SshClientCliSupport() {
        super();
    }

    public static boolean isArgumentedOption(String portOption, String argName) {
        return portOption.equals(argName)
             || "-io".equals(argName)
             || "-i".equals(argName)
             || "-o".equals(argName)
             || "-l".equals(argName)
             || "-w".equals(argName)
             || "-c".equals(argName)
             || "-m".equals(argName)
             || "-E".equals(argName);
    }

    // NOTE: ClientSession#getFactoryManager is the SshClient
    public static ClientSession setupClientSession(
            String portOption, BufferedReader stdin, Level level, PrintStream stdout, PrintStream stderr, String... args)
                throws Exception {
        int port = -1;
        String host = null;
        String login = null;
        String password = null;
        boolean error = false;
        List<Path> identities = new ArrayList<>();
        Map<String, Object> options = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<NamedFactory<Cipher>> ciphers = null;
        List<NamedFactory<Mac>> macs = null;
        List<NamedFactory<Compression>> compressions = null;
        int numArgs = GenericUtils.length(args);
        for (int i = 0; (!error) && (i < numArgs); i++) {
            String argName = args[i];
            String argVal = null;
            if (isArgumentedOption(portOption, argName)) {
                i++;
                if (i >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                argVal = args[i];
            }

            if (portOption.equals(argName)) {
                if (port > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + port);
                    break;
                }

                port = Integer.parseInt(argVal);
                if (port <= 0) {
                    error = showError(stderr, "Bad option value for " + argName + ": " + port);
                    break;
                }
            } else if ("-w".equals(argName)) {
                if (GenericUtils.length(password) > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + password);
                    break;
                }
                password = argVal;
            } else if ("-c".equals(argName)) {
                ciphers = setupCiphers(argName, argVal, ciphers, stderr);
                if (GenericUtils.isEmpty(ciphers)) {
                    error = true;
                    break;
                }
            } else if ("-m".equals(argName)) {
                macs = setupMacs(argName, argVal, macs, stderr);
                if (GenericUtils.isEmpty(macs)) {
                    error = true;
                    break;
                }
            } else if ("-i".equals(argName)) {
                Path idFile = resolveIdentityFile(argVal);
                identities.add(idFile);
            } else if ("-C".equals(argName)) {
                compressions = setupCompressions(argName,
                    GenericUtils.join(
                        Arrays.asList(
                            BuiltinCompressions.Constants.ZLIB, BuiltinCompressions.Constants.DELAYED_ZLIB), ','),
                    compressions, stderr);
                if (GenericUtils.isEmpty(compressions)) {
                    error = true;
                    break;
                }
            } else if ("-o".equals(argName)) {
                String opt = argVal;
                int idx = opt.indexOf('=');
                if (idx <= 0) {
                    error = showError(stderr, "bad syntax for option: " + opt);
                    break;
                }

                String optName = opt.substring(0, idx);
                String optValue = opt.substring(idx + 1);
                if (HostConfigEntry.IDENTITY_FILE_CONFIG_PROP.equals(optName)) {
                    Path idFile = resolveIdentityFile(optValue);
                    identities.add(idFile);
                } else {
                    options.put(optName, optValue);
                }
            } else if ("-l".equals(argName)) {
                if (login != null) {
                    error = showError(stderr, argName + " option value re-specified: " + port);
                    break;
                }

                login = argVal;
            } else if (argName.charAt(0) != '-') {
                if (host != null) { // assume part of a command following it
                    break;
                }

                host = argName;
                int pos = host.indexOf('@');  // check if user@host
                if (pos > 0) {
                    if (login == null) {
                        login = host.substring(0, pos);
                        host = host.substring(pos + 1);
                    } else {
                        error = showError(stderr, "Login already specified using -l option (" + login + "): " + host);
                        break;
                    }
                }
            }
        }

        if ((!error) && GenericUtils.isEmpty(host)) {
            error = showError(stderr, "Hostname not specified");
        }

        if (error) {
            return null;
        }

        SshClient client = setupClient(
            options, ciphers, macs, compressions, identities,
            stdin, stdout, stderr, level, args);
        if (client == null) {
            return null;
        }

        try {
            client.start();

            if (login == null) {
                login = OsUtils.getCurrentUser();
            }

            if (port <= 0) {
                port = SshConstants.DEFAULT_PORT;
            }

            // TODO use a configurable wait time
            ClientSession session = client.connect(login, host, port).verify().getSession();
            try {
                if (GenericUtils.length(password) > 0) {
                    session.addPasswordIdentity(password);
                }
                session.auth().verify(FactoryManager.DEFAULT_AUTH_TIMEOUT);    // TODO use a configurable wait time
                return session;
            } catch (Exception e) {
                session.close(true);
                throw e;
            }
        } catch (Exception e) {
            client.close();
            throw e;
        }
    }

    public static Path resolveIdentityFile(String id) throws IOException {
        BuiltinIdentities identity = BuiltinIdentities.fromName(id);
        if (identity != null) {
            String fileName = ClientIdentity.getIdentityFileName(identity.getName());
            Path keysFolder = PublicKeyEntry.getDefaultKeysFolderPath();
            return keysFolder.resolve(fileName);
        } else {
            return Paths.get(id);
        }
    }

    public static SshClient setupDefaultClient(
            Map<String, ?> options, Level level, PrintStream stdout, PrintStream stderr, String... args) {
        return setupIoServiceFactory(SshClient.setUpDefaultClient(), options, level, stdout, stderr, args);
    }

    // returns null if error encountered
    @SuppressWarnings("checkstyle:ParameterNumber")
    public static SshClient setupClient(
            Map<String, Object> options,
            List<NamedFactory<Cipher>> ciphers,
            List<NamedFactory<Mac>> macs,
            List<NamedFactory<Compression>> compressions,
            Collection<? extends Path> identities,
            BufferedReader stdin, PrintStream stdout, PrintStream stderr,
            Level level, String[] args)
                throws Exception {
        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(options);
        if (GenericUtils.isEmpty(ciphers)) {
            ciphers = setupCiphers(resolver, stderr);
            if (ciphers == null) {
                return null;
            }
        }

        if (GenericUtils.isEmpty(macs)) {
            macs = setupMacs(resolver, stderr);
            if (macs == null) {
                return null;
            }
        }

        if (GenericUtils.isEmpty(compressions)) {
            compressions = setupCompressions(resolver, stderr);
            if (compressions == null) {
                return null;
            }
        }

        SshClient client = setupDefaultClient(options, level, stdout, stderr, args);
        if (client == null) {
            return null;
        }

        try {
            if (GenericUtils.size(ciphers) > 0) {
                client.setCipherFactories(ciphers);
            }

            if (GenericUtils.size(macs) > 0) {
                client.setMacFactories(macs);
            }

            if (GenericUtils.size(compressions) > 0) {
                client.setCompressionFactories(compressions);
            }

            try {
                setupSessionIdentities(client, identities, stdin, stdout, stderr);
            } catch (Throwable t) { // show but do not fail the setup - maybe a password can be used
                showError(stderr, t.getClass().getSimpleName() + " while loading user keys: " + t.getMessage());
            }

            setupServerKeyVerifier(client, options, stdin, stdout, stderr);
            setupSessionUserInteraction(client, stdin, stdout, stderr);

            Map<String, Object> props = client.getProperties();
            props.putAll(options);
            return client;
        } catch (Throwable t) {
            showError(stderr, "Failed (" + t.getClass().getSimpleName() + ") to setup client: " + t.getMessage());
            client.close();
            return null;
        }
    }

    public static FileKeyPairProvider setupSessionIdentities(
            ClientFactoryManager client, Collection<? extends Path> identities,
            BufferedReader stdin, PrintStream stdout, PrintStream stderr)
                throws Throwable {
        client.setFilePasswordProvider((session, file, index) -> {
            stdout.print("Enter password for private key file=" + file + ": ");
            return stdin.readLine();
        });

        if (GenericUtils.isEmpty(identities)) {
            return null;
        }

        FileKeyPairProvider provider = new FileKeyPairProvider() {
            @Override
            public String toString() {
                return FileKeyPairProvider.class.getSimpleName() + "[clientIdentitiesProvider]";
            }
        };
        provider.setPaths(identities);
        client.setKeyIdentityProvider(provider);
        return provider;
    }

    public static UserInteraction setupSessionUserInteraction(
            ClientAuthenticationManager client, BufferedReader stdin, PrintStream stdout, PrintStream stderr) {
        UserInteraction ui = new UserInteraction() {
            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public void serverVersionInfo(ClientSession session, List<String> lines) {
                for (String l : lines) {
                    stdout.append('\t').println(l);
                }
            }

            @Override
            public void welcome(ClientSession clientSession, String banner, String lang) {
                stdout.println(banner);
            }

            @Override
            public String[] interactive(ClientSession clientSession, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                int numPropmts = GenericUtils.length(prompt);
                String[] answers = new String[numPropmts];
                try {
                    for (int i = 0; i < numPropmts; i++) {
                        stdout.append(prompt[i]).print(" ");
                        answers[i] = stdin.readLine();
                    }
                } catch (IOException e) {
                    stderr.append("WARNING: ").append(e.getClass().getSimpleName())
                        .append(" while read prompts: ").println(e.getMessage());
                }
                return answers;
            }

            @Override
            public String getUpdatedPassword(ClientSession clientSession, String prompt, String lang) {
                stdout.append(prompt).print(" ");
                try {
                    return stdin.readLine();
                } catch (IOException e) {
                    stderr.append("WARNING: ").append(e.getClass().getSimpleName())
                        .append(" while read password: ").println(e.getMessage());
                    return null;
                }
            }
        };
        client.setUserInteraction(ui);
        return ui;
    }

    public static ServerKeyVerifier setupServerKeyVerifier(
            ClientAuthenticationManager manager, Map<String, ?> options, BufferedReader stdin, PrintStream stdout, PrintStream stderr) {
        ServerKeyVerifier current = manager.getServerKeyVerifier();
        if (current == null) {
            current = ClientBuilder.DEFAULT_SERVER_KEY_VERIFIER;
            manager.setServerKeyVerifier(current);
        }

        String strictValue = Objects.toString(options.remove(KnownHostsServerKeyVerifier.STRICT_CHECKING_OPTION), "true");
        if (!ConfigFileReaderSupport.parseBooleanValue(strictValue)) {
            return current;
        }

        String filePath = Objects.toString(options.remove(KnownHostsServerKeyVerifier.KNOWN_HOSTS_FILE_OPTION), null);
        if (GenericUtils.isEmpty(filePath)) {
            current = new DefaultKnownHostsServerKeyVerifier(current);
        } else {    // if user specifies a different location than default be lenient
            current = new DefaultKnownHostsServerKeyVerifier(current, false, Paths.get(filePath));
        }

        ((KnownHostsServerKeyVerifier) current).setModifiedServerKeyAcceptor((clientSession, remoteAddress, entry, expected, actual) -> {
            stderr.append("WARNING: Mismatched keys presented by ").append(Objects.toString(remoteAddress))
                  .append(" for entry=").println(entry);
            stderr.append("    ").append("Expected=").append(KeyUtils.getKeyType(expected))
                  .append('-').println(KeyUtils.getFingerPrint(expected));
            stderr.append("    ").append("Actual=").append(KeyUtils.getKeyType(actual))
                  .append('-').println(KeyUtils.getFingerPrint(actual));
            stderr.flush(); // just making sure

            stdout.append("Accept key and update known hosts: y/[N]");
            stdout.flush(); // just making sure

            String ans = GenericUtils.trimToEmpty(stdin.readLine());
            return (GenericUtils.length(ans) > 0) && (Character.toLowerCase(ans.charAt(0)) == 'y');
        });

        manager.setServerKeyVerifier(current);
        return current;
    }

    public static OutputStream resolveLoggingTargetStream(PrintStream stdout, PrintStream stderr, String... args) {
        return resolveLoggingTargetStream(stdout, stderr, args, GenericUtils.length(args));
    }

    public static OutputStream resolveLoggingTargetStream(PrintStream stdout, PrintStream stderr, String[] args, int maxIndex) {
        for (int index = 0; index < maxIndex; index++) {
            String argName = args[index];
            if ("-E".equals(argName)) {
                if ((index + 1) >= maxIndex) {
                    showError(stderr, "Missing " + argName + " option argument");
                    return null;
                }

                String argVal = args[index + 1];
                if ("--".equals(argVal)) {
                    return stdout;
                }

                try {
                    Path path = Paths.get(argVal).normalize().toAbsolutePath();
                    return Files.newOutputStream(path);
                } catch (IOException e) {
                    showError(stderr, "Failed (" + e.getClass().getSimpleName() + ") to open " + argVal + ": " + e.getMessage());
                    return null;
                }
            }
        }

        return stderr;
    }

    public static List<NamedFactory<Compression>> setupCompressions(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(options, ConfigFileReaderSupport.COMPRESSION_PROP);
        if (GenericUtils.isEmpty(argVal)) {
            return Collections.emptyList();
        }

        NamedFactory<Compression> value = CompressionConfigValue.fromName(argVal);
        if (value == null) {
            showError(stderr, "Unknown compression configuration value: " + argVal);
            return null;
        }

        return Collections.singletonList(value);
    }

    public static List<NamedFactory<Compression>> setupCompressions(
            String argName, String argVal, List<NamedFactory<Compression>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinCompressions.ParseResult result = BuiltinCompressions.parseCompressionsList(argVal);
        Collection<? extends NamedFactory<Compression>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            showError(stderr, "No known compressions in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported compressions: ").println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }

    public static List<NamedFactory<Mac>> setupMacs(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(options, ConfigFileReaderSupport.MACS_CONFIG_PROP);
        return GenericUtils.isEmpty(argVal)
             ? Collections.emptyList()
             : setupMacs(ConfigFileReaderSupport.MACS_CONFIG_PROP, argVal, null, stderr);
    }

    public static List<NamedFactory<Mac>> setupMacs(String argName, String argVal, List<NamedFactory<Mac>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(argVal);
        Collection<? extends NamedFactory<Mac>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            showError(stderr, "No known MACs in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported MACs: ").println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }

    public static List<NamedFactory<Cipher>> setupCiphers(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(options, ConfigFileReaderSupport.CIPHERS_CONFIG_PROP);
        return GenericUtils.isEmpty(argVal)
             ? Collections.emptyList()
             : setupCiphers(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP, argVal, null, stderr);
    }

    // returns null - e.g., re-specified or no supported cipher found
    public static List<NamedFactory<Cipher>> setupCiphers(String argName, String argVal, List<NamedFactory<Cipher>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(argVal);
        Collection<? extends NamedFactory<Cipher>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            showError(stderr, "WARNING: No known ciphers in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported ciphers: ").println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }

    public static Handler setupLogging(Level level, PrintStream stdout, PrintStream stderr, OutputStream outputStream) {
        Handler fh = new ConsoleHandler() {
            {
                setOutputStream(outputStream); // override the default (stderr)
            }

            @Override
            protected synchronized void setOutputStream(OutputStream out) throws SecurityException {
                if ((out == stdout) || (out == stderr)) {
                    super.setOutputStream(new NoCloseOutputStream(out));
                } else {
                    super.setOutputStream(out);
                }
            }
        };
        fh.setLevel(Level.FINEST);
        fh.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String message = formatMessage(record);
                String throwable = "";
                Throwable t = record.getThrown();
                if (t != null) {
                    StringWriter sw = new StringWriter();
                    try (PrintWriter pw = new PrintWriter(sw)) {
                        pw.println();
                        t.printStackTrace(pw);  // NOPMD
                    }
                    throwable = sw.toString();
                }
                return String.format("%1$tY-%1$tm-%1$td: %2$-7.7s: %3$-32.32s: %4$s%5$s%n",
                        new Date(record.getMillis()), record.getLevel().getName(),
                        record.getLoggerName(), message, throwable);
            }
        });

        Logger root = Logger.getLogger("");
        for (Handler handler : root.getHandlers()) {
            root.removeHandler(handler);
        }
        root.addHandler(fh);
        root.setLevel(level);
        return fh;
    }
}
