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

import java.util.EnumMap;
import java.util.Map;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PtyChannelConfiguration implements PtyChannelConfigurationMutator {
    private String ptyType;
    private int ptyColumns = DEFAULT_COLUMNS_COUNT;
    private int ptyLines = DEFAULT_ROWS_COUNT;
    private int ptyWidth = DEFAULT_WIDTH;
    private int ptyHeight = DEFAULT_HEIGHT;
    private Map<PtyMode, Integer> ptyModes = new EnumMap<>(PtyMode.class);

    public PtyChannelConfiguration() {
        ptyModes.putAll(DEFAULT_PTY_MODES);
    }

    @Override
    public String getPtyType() {
        return ptyType;
    }

    @Override
    public void setPtyType(String ptyType) {
        this.ptyType = ptyType;
    }

    @Override
    public int getPtyColumns() {
        return ptyColumns;
    }

    @Override
    public void setPtyColumns(int ptyColumns) {
        this.ptyColumns = ptyColumns;
    }

    @Override
    public int getPtyLines() {
        return ptyLines;
    }

    @Override
    public void setPtyLines(int ptyLines) {
        this.ptyLines = ptyLines;
    }

    @Override
    public int getPtyWidth() {
        return ptyWidth;
    }

    @Override
    public void setPtyWidth(int ptyWidth) {
        this.ptyWidth = ptyWidth;
    }

    @Override
    public int getPtyHeight() {
        return ptyHeight;
    }

    @Override
    public void setPtyHeight(int ptyHeight) {
        this.ptyHeight = ptyHeight;
    }

    @Override
    public Map<PtyMode, Integer> getPtyModes() {
        return ptyModes;
    }

    @Override
    public void setPtyModes(Map<PtyMode, Integer> ptyModes) {
        this.ptyModes = ptyModes;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[type=" + getPtyType()
               + ", lines=" + getPtyLines()
               + ", columns=" + getPtyColumns()
               + ", height=" + getPtyHeight()
               + ", width=" + getPtyWidth()
               + ", modes=" + getPtyModes()
               + "]";
    }
}
