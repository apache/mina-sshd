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
package org.apache.sshd.git.pgm;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.pgm.CommandCatalog;
import org.eclipse.jgit.pgm.CommandRef;
import org.eclipse.jgit.pgm.Die;
import org.eclipse.jgit.pgm.TextBuiltin;
import org.eclipse.jgit.pgm.internal.CLIText;
import org.eclipse.jgit.pgm.opt.CmdLineParser;
import org.eclipse.jgit.pgm.opt.SubcommandHandler;
import org.eclipse.jgit.util.io.ThrowingPrintWriter;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EmbeddedCommandRunner {
    @Option(name = "--help", usage = "usage_displayThisHelpText", aliases = { "-h" })
    private boolean help;

    @Option(name = "--show-stack-trace", usage = "usage_displayThejavaStackTraceOnExceptions")
    private boolean showStackTrace;

    @Option(name = "--git-dir", metaVar = "metaVar_gitDir", usage = "usage_setTheGitRepositoryToOperateOn")
    private String gitdir;

    @Argument(index = 0, metaVar = "metaVar_command", required = true, handler = SubcommandHandler.class)
    private TextBuiltin subcommand;

    @Argument(index = 1, metaVar = "metaVar_arg")
    private List<String> arguments = new ArrayList<>();

    private Path rootDir;

    public EmbeddedCommandRunner(Path rootDir) {
        this.rootDir = Objects.requireNonNull(rootDir, "No root directory specified");
    }

    /**
     * Execute a command.
     *
     * @param  argv      the command and its arguments
     * @param  in        the input stream, may be null in which case the system input stream will be used
     * @param  out       the output stream, may be null in which case the system output stream will be used
     * @param  err       the error stream, may be null in which case the system error stream will be used
     * @throws Exception if an error occurs
     */
    public void execute(String[] argv, InputStream in, OutputStream out, OutputStream err) throws Exception {
        CmdLineParser clp = new CmdLineParser(this);
        PrintWriter writer = new PrintWriter(err != null ? err : System.err);
        try {
            clp.parseArgument(argv);
        } catch (CmdLineException e) {
            if (argv.length > 0 && !help) {
                writer.println(MessageFormat.format(CLIText.get().fatalError, e.getMessage()));
                writer.flush();
                throw new Die(true);
            }
        }

        if (argv.length == 0 || help) {
            String ex = clp.printExample(OptionHandlerFilter.ALL, CLIText.get().resourceBundle());
            writer.println("jgit" + ex + " command [ARG ...]"); //$NON-NLS-1$
            if (help) {
                writer.println();
                clp.printUsage(writer, CLIText.get().resourceBundle());
                writer.println();
            } else if (subcommand == null) {
                writer.println();
                writer.println(CLIText.get().mostCommonlyUsedCommandsAre);
                final CommandRef[] common = CommandCatalog.common();
                int width = 0;
                for (final CommandRef c : common) {
                    width = Math.max(width, c.getName().length());
                }
                width += 2;

                for (final CommandRef c : common) {
                    writer.print(' ');
                    writer.print(c.getName());
                    for (int i = c.getName().length(); i < width; i++) {
                        writer.print(' ');
                    }
                    writer.print(CLIText.get().resourceBundle().getString(c.getUsage()));
                    writer.println();
                }
                writer.println();
            }
            writer.flush();
            throw new Die(true);
        }

        gitdir = Objects.toString(rootDir.resolve(gitdir));

        TextBuiltin cmd = subcommand;
        set(cmd, "ins", in);
        set(cmd, "outs", out);
        set(cmd, "errs", err);

        Boolean success = (Boolean) call(cmd, "requiresRepository");
        if (success) {
            call(cmd, "init", new Class[] { Repository.class, String.class }, new Object[] { openGitDir(gitdir), gitdir });
        } else {
            call(cmd, "init", new Class[] { Repository.class, String.class }, new Object[] { null, gitdir });
        }
        try {
            cmd.execute(arguments.toArray(new String[arguments.size()]));
        } finally {
            if (get(cmd, "outw") != null) {
                ((ThrowingPrintWriter) get(cmd, "outw")).flush();
            }
            if (get(cmd, "errw") != null) {
                ((ThrowingPrintWriter) get(cmd, "errw")).flush();
            }
        }
    }

    private Object get(Object obj, String name) throws IllegalAccessException, NoSuchFieldException {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private void set(Object obj, String name, Object val) throws IllegalAccessException, NoSuchFieldException {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                field.set(obj, val);
                return;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private Object call(Object obj, String name)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return call(obj, name, new Class[0], new Object[0]);
    }

    private Object call(Object obj, String name, Class<?>[] types, Object[] args)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Method method = clazz.getDeclaredMethod(name, types);
                method.setAccessible(true);
                return method.invoke(obj, args);
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException(name);
    }

    /**
     * Evaluate the {@code --git-dir} option and open the repository.
     *
     * @param  gitdir      the {@code --git-dir} option given on the command line. May be null if it was not supplied.
     * @return             the repository to operate on.
     * @throws IOException the repository cannot be opened.
     */
    protected Repository openGitDir(String gitdir) throws IOException {
        return Git.open(new File(gitdir)).getRepository();
        /*
         * RepositoryBuilder rb = new RepositoryBuilder() // .setGitDir(gitdir != null ? new File(gitdir) : null) //
         * .readEnvironment() // .findGitDir(); if (rb.getGitDir() == null) throw new
         * Die(CLIText.get().cantFindGitDirectory); return rb.build();
         */
    }
}
