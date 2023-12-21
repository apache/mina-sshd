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

package org.apache.sshd.common.session.helpers;

/**
 * Provides several internal session counters details
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SessionCountersDetails {
    private long inputPacketSequenceNumber;
    private long outputPacketSequenceNumber;
    private long inputPacketsCount;
    private long outputPacketsCount;
    private long totalIncomingPacketsCount;
    private long totalOutgoingPacketsCount;
    private long inputBytesCount;
    private long outputBytesCount;
    private long totalIncomingBytesCount;
    private long totalOutgoingBytesCount;
    private long inputBlocksCount;
    private long outputBlocksCount;
    private long totalIncomingBlocksCount;
    private long totalOutgoingBlocksCount;

    public SessionCountersDetails() {
        super();
    }

    public long getInputPacketSequenceNumber() {
        return inputPacketSequenceNumber;
    }

    public void setInputPacketSequenceNumber(long inputPacketSequenceNumber) {
        this.inputPacketSequenceNumber = inputPacketSequenceNumber;
    }

    public long getOutputPacketSequenceNumber() {
        return outputPacketSequenceNumber;
    }

    public void setOutputPacketSequenceNumber(long outputPacketSequenceNumber) {
        this.outputPacketSequenceNumber = outputPacketSequenceNumber;
    }

    public long getInputPacketsCount() {
        return inputPacketsCount;
    }

    public void setInputPacketsCount(long inputPacketsCount) {
        this.inputPacketsCount = inputPacketsCount;
    }

    public long getOutputPacketsCount() {
        return outputPacketsCount;
    }

    public void setOutputPacketsCount(long outputPacketsCount) {
        this.outputPacketsCount = outputPacketsCount;
    }

    public long getTotalIncomingPacketsCount() {
        return totalIncomingPacketsCount;
    }

    public void setTotalIncomingPacketsCount(long totalIncomingPacketsCount) {
        this.totalIncomingPacketsCount = totalIncomingPacketsCount;
    }

    public long getTotalOutgoingPacketsCount() {
        return totalOutgoingPacketsCount;
    }

    public void setTotalOutgoingPacketsCount(long totalOutgoingPacketsCount) {
        this.totalOutgoingPacketsCount = totalOutgoingPacketsCount;
    }

    public long getInputBytesCount() {
        return inputBytesCount;
    }

    public void setInputBytesCount(long inputBytesCount) {
        this.inputBytesCount = inputBytesCount;
    }

    public long getOutputBytesCount() {
        return outputBytesCount;
    }

    public void setOutputBytesCount(long outputBytesCount) {
        this.outputBytesCount = outputBytesCount;
    }

    public long getTotalIncomingBytesCount() {
        return totalIncomingBytesCount;
    }

    public void setTotalIncomingBytesCount(long totalIncomingBytesCount) {
        this.totalIncomingBytesCount = totalIncomingBytesCount;
    }

    public long getTotalOutgoingBytesCount() {
        return totalOutgoingBytesCount;
    }

    public void setTotalOutgoingBytesCount(long totalOutgoingBytesCount) {
        this.totalOutgoingBytesCount = totalOutgoingBytesCount;
    }

    public long getInputBlocksCount() {
        return inputBlocksCount;
    }

    public void setInputBlocksCount(long inputBlocksCount) {
        this.inputBlocksCount = inputBlocksCount;
    }

    public long getOutputBlocksCount() {
        return outputBlocksCount;
    }

    public void setOutputBlocksCount(long outputBlocksCount) {
        this.outputBlocksCount = outputBlocksCount;
    }

    public long getTotalIncomingBlocksCount() {
        return totalIncomingBlocksCount;
    }

    public void setTotalIncomingBlocksCount(long totalIncomingBlocksCount) {
        this.totalIncomingBlocksCount = totalIncomingBlocksCount;
    }

    public long getTotalOutgoingBlocksCount() {
        return totalOutgoingBlocksCount;
    }

    public void setTotalOutgoingBlocksCount(long totalOutgoingBlocksCount) {
        this.totalOutgoingBlocksCount = totalOutgoingBlocksCount;
    }
}
