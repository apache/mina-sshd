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
package org.apache.sshd.benchmarks;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public final class RunBenchmarks {

    @Option(name = "--run", aliases = "{ -r }", metaVar = "REGEX",
            usage = "Tests to run. If not given, runs all SftpUploadBenchmarks.")
    private String include = "SftpUploadBenchmark";

    @Option(name = "--server", aliases = "{ -s }", metaVar = "USER@HOSTNAME:PORT",
            usage = "Specifies the hostname to connect to. At least USER and HOSTNAME must be given. If absent, a local container will be used (and the docker engine must be running).")
    private String server;

    @Option(name = "--identity", aliases = "{ -i }", metaVar = "PRIVATE_KEY_FILE",
            usage = "The SSH private key to connect to the host. Mandatory if --server is given; otherwise ignored. If it starts with ~/ or ~\\, the ~ is replaced by the user's home directory.")
    private String userKey;

    @Option(name = "--help", aliases = { "-h" }, usage = "Displays this help text and exits.")
    private boolean help;

    private String user;
    private String hostname;
    private Path key;
    private int port;

    private RunBenchmarks() {
        super();
    }

    private void run(String... args) throws Exception {
        if (!parseArguments(args)) {
            return;
        }
        TestServer.INSTANCE.start(user, hostname, port, key);
        try {
            Options opt = new OptionsBuilder() //
                    .include(include) //
                    .param("sftpHost", TestServer.INSTANCE.getHost()) //
                    .param("sftpPort", Integer.toString(TestServer.INSTANCE.getPort())) //
                    .param("sftpUser", TestServer.INSTANCE.getUser()) //
                    .param("sftpKey", TestServer.INSTANCE.getPrivateKey().toString()) //
                    .param("initialFile", TestServer.INSTANCE.getFile().toString()) //
                    .mode(Mode.AverageTime) //
                    .warmupIterations(4) //
                    .measurementIterations(10) //
                    .shouldFailOnError(true) //
                    .timeUnit(TimeUnit.MILLISECONDS) //
                    .forks(1) //
                    .threads(1) //
                    .build();
            new Runner(opt).run();
        } finally {
            TestServer.INSTANCE.stop();
        }
    }

    private boolean parseArguments(String... args) {
        CmdLineParser parser = new CmdLineParser(this);
        try {
            parser.parseArgument(args);
            if (help) {
                printUsage(parser);
                return false;
            }
            return splitServer();
        } catch (CmdLineException err) {
            System.err.println("Invalid arguments, try --help: " + err.getLocalizedMessage());
            return false;
        }
    }

    private boolean splitServer() {
        if (server == null) {
            return true;
        }
        try {
            server = server.trim();
            int i = server.indexOf('@');
            if (i < 0) {
                throw new IllegalArgumentException("no user name");
            }
            user = server.substring(0, i).trim();
            if (user.isEmpty()) {
                throw new IllegalArgumentException("no user name");
            }
            int j = server.indexOf(':', i);
            if (j > i) {
                hostname = server.substring(i + 1, j).trim();
                port = Integer.parseUnsignedInt(server.substring(j + 1));
            } else {
                hostname = server.substring(i + 1).trim();
                port = 22;
            }
            if (port < 1024 && port != 22 || port > 65535) {
                throw new IllegalArgumentException("invalid port " + port);
            }
            if (hostname.isEmpty()) {
                throw new IllegalArgumentException("no host name");
            }
            if (userKey == null || userKey.isEmpty()) {
                throw new IllegalArgumentException("need a private key when a host is specified");
            }
            if (userKey.startsWith("~/") || userKey.startsWith('~' + File.separator)) {
                String homeDir = System.getProperty("user.home");
                key = Paths.get(homeDir, userKey.substring(2));
            } else {
                key = Paths.get(userKey);
            }
            if (!Files.isRegularFile(key)) {
                throw new IllegalArgumentException("private key " + userKey + " not found or not a file");
            }
            return true;
        } catch (IllegalArgumentException e) {
            System.err.println(
                    "Server must have the format USER@HOSTNAME or USER@HOSTNAME:PORT, and there must be a private key. Try --help. Error: "
                               + e.getLocalizedMessage());
            return false;
        }
    }

    private void printUsage(CmdLineParser parser) {
        System.err.print("SftpBenchmarks ");
        parser.printSingleLineUsage(System.err);
        System.err.println();

        System.err.println();
        parser.printUsage(System.err);
        System.err.println();

        System.err.flush();
    }

    public static void main(String... args) throws Exception {
        RunBenchmarks exec = new RunBenchmarks();
        exec.run(args);
    }

}
