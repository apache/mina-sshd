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

package org.apache.sshd.server.command;

/**
 * Represents a {@link CommandFactory} that filters the commands it recognizes
 * and delegates the ones it doesn't to another delegate factory. The behavior
 * of such a delegating factory is undefined if it receives a command it does
 * not recognize and not delegate has been set. The recommended behavior in this
 * case is to throw some exception - though this is not mandatory
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface DelegatingCommandFactory extends CommandFactory {
    CommandFactory getDelegateCommandFactory();

    void setDelegateCommandFactory(CommandFactory factory);

    /**
     * @param command The command about to be executed
     * @return {@code true} if this command is supported by the command
     * factory, {@code false} if it will be passed on to the
     * {@link #getDelegateCommandFactory() delegate} factory
     */
    boolean isSupportedCommand(String command);
}
