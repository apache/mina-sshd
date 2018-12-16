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

package org.apache.sshd.cli.server;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.Level;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.config.keys.ServerIdentity;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.apache.sshd.server.shell.ShellFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshServerMain extends SshServerCliSupport {
    public SshServerMain() {
        super();    // in case someone wants to extend it
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        int port = 8000;
        boolean error = false;
        String hostKeyType = AbstractGeneratorHostKeyProvider.DEFAULT_ALGORITHM;
        int hostKeySize = 0;
        Collection<String> keyFiles = null;
        Map<String, Object> options = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        int numArgs = GenericUtils.length(args);
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            if ("-p".equals(argName)) {
                i++;
                if (i >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }
                port = Integer.parseInt(args[i]);
            } else if ("-key-type".equals(argName)) {
                i++;
                if (i >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                if (keyFiles != null) {
                    System.err.println("option conflicts with -key-file: " + argName);
                    error = true;
                    break;
                }
                hostKeyType = args[i].toUpperCase();
            } else if ("-key-size".equals(argName)) {
                i++;
                if (i >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                if (keyFiles != null) {
                    System.err.println("option conflicts with -key-file: " + argName);
                    error = true;
                    break;
                }

                hostKeySize = Integer.parseInt(args[i]);
            } else if ("-key-file".equals(argName)) {
                i++;
                if (i >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                String keyFilePath = args[i];
                if (keyFiles == null) {
                    keyFiles = new LinkedList<>();
                }
                keyFiles.add(keyFilePath);
            } else if ("-o".equals(argName)) {
                i++;
                if (i >= numArgs) {
                    System.err.println("option requires and argument: " + argName);
                    error = true;
                    break;
                }

                String opt = args[i];
                int idx = opt.indexOf('=');
                if (idx <= 0) {
                    System.err.println("bad syntax for option: " + opt);
                    error = true;
                    break;
                }

                String optName = opt.substring(0, idx);
                String optValue = opt.substring(idx + 1);
                if (ServerIdentity.HOST_KEY_CONFIG_PROP.equals(optName)) {
                    if (keyFiles == null) {
                        keyFiles = new LinkedList<>();
                    }
                    keyFiles.add(optValue);
                } else if (ConfigFileReaderSupport.PORT_CONFIG_PROP.equals(optName)) {
                    port = Integer.parseInt(optValue);
                } else {
                    options.put(optName, optValue);
                }
            }
        }

        Level level = resolveLoggingVerbosity(options, args);
        SshServer sshd = error
            ? null
            : setupIoServiceFactory(SshServer.setUpDefaultServer(), options, level, System.out, System.err, args);
        if (sshd == null) {
            error = true;
        }

        if (error) {
            System.err.println("usage: sshd [-p port] [-io mina|nio2|netty] [-key-type RSA|DSA|EC] [-key-size NNNN] [-key-file <path>] [-o option=value]");
            System.exit(-1);
        }

        Map<String, Object> props = sshd.getProperties();
        props.putAll(options);

        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(options);
        KeyPairProvider hostKeyProvider = resolveServerKeys(System.err, hostKeyType, hostKeySize, keyFiles);
        sshd.setKeyPairProvider(hostKeyProvider);
        // Should come AFTER key pair provider setup so auto-welcome can be generated if needed
        setupServerBanner(sshd, resolver);
        sshd.setPort(port);

        String macsOverride = resolver.getString(ConfigFileReaderSupport.MACS_CONFIG_PROP);
        if (GenericUtils.isNotEmpty(macsOverride)) {
            SshConfigFileReader.configureMacs(sshd, macsOverride, true, true);
        }

        ShellFactory shellFactory = resolveShellFactory(System.err, resolver);
        if (shellFactory != null) {
            System.out.append("Using shell=").println(shellFactory.getClass().getName());
            sshd.setShellFactory(shellFactory);
        }

        sshd.setPasswordAuthenticator((username, password, session) -> Objects.equals(username, password));
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        setupServerForwarding(sshd, level, System.out, System.err, resolver);
        sshd.setCommandFactory(new ScpCommandFactory.Builder()
            .withDelegate(ProcessShellCommandFactory.INSTANCE)
            .build());

        List<NamedFactory<Command>> subsystems =
            resolveServerSubsystems(level, System.out, System.err, resolver);
        if (GenericUtils.isNotEmpty(subsystems)) {
            System.out.append("Setup subsystems=").println(NamedResource.getNames(subsystems));
            sshd.setSubsystemFactories(subsystems);
        }

        System.err.println("Starting SSHD on port " + port);
        sshd.start();
        Thread.sleep(Long.MAX_VALUE);
        System.err.println("Exiting after a very (very very) long time");
    }
}
