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
package org.apache.sshd.cli;

import java.io.PrintStream;

import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.util.GenericUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class CliSupport {
    public static final BuiltinIoServiceFactoryFactories DEFAULT_IO_SERVICE_FACTORY = BuiltinIoServiceFactoryFactories.NIO2;

    protected CliSupport() {
        super();
    }

    public static boolean showError(PrintStream stderr, String message) {
        stderr.println(message);
        return true;
    }

    /**
     * Scans the arguments for the &quot;-io&quot; command line option and sets the I/O
     * service accordingly. If no specific option specified then {@link #DEFAULT_IO_SERVICE_FACTORY}
     * is used.
     *
     * @param stderr Error stream for output of error messages
     * @param args The arguments to scan
     * @return The resolved I/O service factory - {@code null} if errors encountered
     */
    public static BuiltinIoServiceFactoryFactories resolveIoServiceFactory(PrintStream stderr, String... args) {
        int numArgs = GenericUtils.length(args);
        BuiltinIoServiceFactoryFactories factory = null;
        for (int index = 0; index < numArgs; index++) {
            String argName = args[index];
            if (!"-io".equals(argName)) {
                continue;
            }

            if (factory != null) {
                stderr.println("I/O factory re-specified - already set as " + factory);
                return null;
            }

            index++;
            if (index >= numArgs) {
                stderr.println("option requires an argument: " + argName);
                return null;
            }

            String provider = args[index];
            factory = BuiltinIoServiceFactoryFactories.fromFactoryName(provider);
            if (factory == null) {
                System.err.println("provider (" + argName + ") should be one of " + BuiltinIoServiceFactoryFactories.VALUES);
                return null;
            }
        }

        if (factory == null) {
            factory = DEFAULT_IO_SERVICE_FACTORY;
        }

        System.setProperty(IoServiceFactoryFactory.class.getName(), factory.getFactoryClassName());
        return factory;
    }

    public static <M extends AbstractFactoryManager> M setupIoServiceFactory(M manager, PrintStream stderr, String... args) {
        BuiltinIoServiceFactoryFactories factory = resolveIoServiceFactory(stderr, args);
        if (factory == null) {
            return null;
        }

        manager.setIoServiceFactoryFactory(factory.create());
        return manager;
    }
}
