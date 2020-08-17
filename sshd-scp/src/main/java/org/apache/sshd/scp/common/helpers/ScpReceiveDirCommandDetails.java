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

package org.apache.sshd.scp.common.helpers;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Holds the details of a &quot;Dmmmm <length> <directory>&quot; command - e.g., &quot;D0755 0 dirname&quot;
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpReceiveDirCommandDetails extends ScpPathCommandDetailsSupport {
    public static final String DEFAULT_DIR_OCTAL_PERMISSIONS = "0755";
    public static final char COMMAND_NAME = 'D';

    public ScpReceiveDirCommandDetails() {
        super(COMMAND_NAME);
    }

    public ScpReceiveDirCommandDetails(String header) {
        super(COMMAND_NAME, header);
    }

    @Override   // length is irrelevant for 'D' commands
    protected long getEffectiveLength() {
        return 0L;
    }

    public static ScpReceiveDirCommandDetails parse(String header) {
        return GenericUtils.isEmpty(header) ? null : new ScpReceiveDirCommandDetails(header);
    }
}
