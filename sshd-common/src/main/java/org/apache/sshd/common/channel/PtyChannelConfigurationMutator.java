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

import java.io.IOException;
import java.util.Map;

import org.apache.sshd.common.util.OsUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PtyChannelConfigurationMutator extends PtyChannelConfigurationHolder {
    void setPtyType(String ptyType);

    void setPtyColumns(int ptyColumns);

    void setPtyLines(int ptyLines);

    void setPtyWidth(int ptyWidth);

    void setPtyHeight(int ptyHeight);

    void setPtyModes(Map<PtyMode, Integer> ptyModes);

    static <M extends PtyChannelConfigurationMutator> M copyConfiguration(PtyChannelConfigurationHolder src, M dst) {
        if ((src == null) || (dst == null)) {
            return dst;
        }

        dst.setPtyColumns(src.getPtyColumns());
        dst.setPtyHeight(src.getPtyHeight());
        dst.setPtyLines(src.getPtyLines());
        dst.setPtyModes(src.getPtyModes());
        dst.setPtyType(src.getPtyType());
        dst.setPtyWidth(src.getPtyWidth());
        return dst;
    }

    /**
     * Uses O/S detection to initialize some default PTY related values
     *
     * @param  <M>                  Generic {@link PtyChannelConfigurationMutator} instance
     * @param  mutator              The mutator to update - ignored if {@code null}
     * @return                      The updated mutator
     * @throws IOException          If failed to access some O/S related configuration
     * @throws InterruptedException If interrupted during access of O/S related configuration
     */
    static <M extends PtyChannelConfigurationMutator> M setupSensitiveDefaultPtyConfiguration(M mutator)
            throws IOException, InterruptedException {
        if (mutator == null) {
            return null;
        }

        if (OsUtils.isUNIX()) {
            mutator.setPtyModes(SttySupport.getUnixPtyModes());
            mutator.setPtyColumns(SttySupport.getTerminalWidth());
            mutator.setPtyLines(SttySupport.getTerminalHeight());
        } else {
            mutator.setPtyType(WINDOWS_PTY_TYPE);
        }

        return mutator;
    }
}
