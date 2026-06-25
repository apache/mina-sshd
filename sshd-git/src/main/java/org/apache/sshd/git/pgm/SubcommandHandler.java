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

import org.eclipse.jgit.pgm.CommandCatalog;
import org.eclipse.jgit.pgm.CommandRef;
import org.eclipse.jgit.pgm.internal.CLIText;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.OptionDef;
import org.kohsuke.args4j.spi.OptionHandler;
import org.kohsuke.args4j.spi.Parameters;
import org.kohsuke.args4j.spi.Setter;

public class SubcommandHandler extends OptionHandler<CommandRef> {
    private final org.eclipse.jgit.pgm.opt.CmdLineParser clp;

    public SubcommandHandler(final CmdLineParser parser, final OptionDef option, final Setter<? super CommandRef> setter) {
        super(parser, option, setter);
        clp = (org.eclipse.jgit.pgm.opt.CmdLineParser) parser;
    }

    /** {@inheritDoc} */
    @Override
    public int parseArguments(Parameters params) throws CmdLineException {
        final String name = params.getParameter(0);
        final CommandRef cr = CommandCatalog.get(name);
        if (cr == null) {
            throw new CmdLineException(clp, CLIText.format(CLIText.get().notAJgitCommand), name);
        }
        // Force option parsing to stop. Everything after us should
        // be arguments known only to this command and must not be
        // recognized by the current parser.
        //
        owner.stopOptionParsing();
        setter.addValue(cr);
        return 1;
    }

    /** {@inheritDoc} */
    @Override
    public String getDefaultMetaVariable() {
        return CLIText.get().metaVar_command;
    }
}
