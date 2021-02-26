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
package org.apache.sshd.util.test;

import org.apache.sshd.server.ExitCallback;

public class BogusExitCallback implements ExitCallback {

    private boolean exited;
    private int exitValue;
    private String exitMessage;
    private boolean closeImmediately;

    public BogusExitCallback() {
        super();
    }

    @Override
    public void onExit(int exitValue, boolean closeImmediately) {
        onExit(exitValue, String.valueOf(exitValue), closeImmediately);
    }

    @Override
    public void onExit(int exitValue, String exitMessage, boolean closeImmediately) {
        this.exited = true;
        this.exitValue = exitValue;
        this.exitMessage = exitMessage;
        this.closeImmediately = closeImmediately;
    }

    public boolean isExited() {
        return exited;
    }

    public int getExitValue() {
        return exitValue;
    }

    public String getExitMessage() {
        return exitMessage;
    }

    public boolean isCloseImmediately() {
        return closeImmediately;
    }
}
