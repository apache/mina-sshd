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

package org.apache.sshd.common.channel;

import java.util.Map;

import org.apache.sshd.common.util.MapEntryUtils.EnumMapBuilder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PtyChannelConfigurationHolder {
    int DEFAULT_COLUMNS_COUNT = 80;
    int DEFAULT_ROWS_COUNT = 24;
    int DEFAULT_WIDTH = 640;
    int DEFAULT_HEIGHT = 480;

    String DUMMY_PTY_TYPE = "dummy";
    String WINDOWS_PTY_TYPE = "windows";

    Map<PtyMode, Integer> DEFAULT_PTY_MODES = EnumMapBuilder.<PtyMode, Integer> builder(PtyMode.class)
            .put(PtyMode.ISIG, 1)
            .put(PtyMode.ICANON, 1)
            .put(PtyMode.ECHO, 1)
            .put(PtyMode.ECHOE, 1)
            .put(PtyMode.ECHOK, 1)
            .put(PtyMode.ECHONL, 0)
            .put(PtyMode.NOFLSH, 0)
            .immutable();

    String getPtyType();

    int getPtyColumns();

    int getPtyLines();

    int getPtyWidth();

    int getPtyHeight();

    Map<PtyMode, Integer> getPtyModes();
}
