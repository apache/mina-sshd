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

package org.apache.sshd.common.subsystem.sftp.extensions;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * @param <T> Parse result type
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractParser<T> implements ExtensionParser<T> {
    private final String name;

    protected AbstractParser(String name) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No extension name");
    }

    @Override
    public final String getName() {
        return name;
    }
}
