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

package org.apache.sshd.sftp.server;

import org.apache.sshd.sftp.common.SftpHelper;

/**
 * Invoked in order to format failed commands messages
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpErrorStatusDataHandler {
    SftpErrorStatusDataHandler DEFAULT = new SftpErrorStatusDataHandler() {
        @Override
        public String toString() {
            return SftpErrorStatusDataHandler.class.getSimpleName() + "[DEFAULT]";
        }
    };

    /**
     * @param  sftpSubsystem The SFTP subsystem instance
     * @param  id            The command identifier
     * @param  e             Thrown exception
     * @param  cmd           The command that was attempted
     * @param  args          The relevant command arguments - <B>Note:</B> provided only for <U>logging</U> purposes and
     *                       subject to type and/or order change at any version
     * @return               The relevant sub-status to send as failure indication for the failed command
     * @see                  SftpHelper#resolveSubstatus(Throwable)
     */
    default int resolveSubStatus(SftpSubsystemEnvironment sftpSubsystem, int id, Throwable e, int cmd, Object... args) {
        return SftpHelper.resolveSubstatus(e);
    }

    /**
     * @param  sftpSubsystem The SFTP subsystem instance
     * @param  id            The command identifier
     * @param  e             Thrown exception
     * @param  subStatus     The sub-status code obtained from invocation of
     *                       {@link #resolveSubStatus(SftpSubsystemEnvironment, int, Throwable, int, Object...)
     *                       resolveSubStatus}
     * @param  cmd           The command that was attempted
     * @param  args          The relevant command arguments - <B>Note:</B> provided only for <U>logging</U> purposes and
     *                       subject to type and/or order change at any version
     * @return               The human readable text message that explains the failure reason
     * @see                  SftpHelper#resolveStatusMessage(int)
     */
    default String resolveErrorMessage(
            SftpSubsystemEnvironment sftpSubsystem, int id, Throwable e, int subStatus, int cmd, Object... args) {
        return SftpHelper.resolveStatusMessage(subStatus);
    }

    /**
     * @param  sftpSubsystem The SFTP subsystem instance
     * @param  id            The command identifier
     * @param  e             Thrown exception
     * @param  subStatus     The sub-status code obtained from invocation of
     *                       {@link #resolveSubStatus(SftpSubsystemEnvironment, int, Throwable, int, Object...)
     *                       resolveSubStatus}
     * @param  cmd           The command that was attempted
     * @param  args          The relevant command arguments - <B>Note:</B> provided only for <U>logging</U> purposes and
     *                       subject to type and/or order change at any version
     * @return               The error message language tag - recommend returning empty string
     */
    default String resolveErrorLanguage(
            SftpSubsystemEnvironment sftpSubsystem, int id, Throwable e, int subStatus, int cmd, Object... args) {
        return "";
    }
}
