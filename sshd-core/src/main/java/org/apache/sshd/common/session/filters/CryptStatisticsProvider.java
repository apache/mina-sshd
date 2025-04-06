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
package org.apache.sshd.common.session.filters;

public interface CryptStatisticsProvider {

    /**
     * Retrieves the previous input sequence number.
     * <p>
     * This is the sequence number of the last received packet.
     * </p>
     *
     * @return the sequence number as an unsigned 32bit value.
     */
    long getLastInputSequenceNumber();

    /**
     * Retrieves the current input sequence number.
     * <p>
     * This is the sequence number expected for the next packet.
     * </p>
     *
     * @return the sequence number as an unsigned 32bit value.
     */
    long getInputSequenceNumber();

    /**
     * Retrieves the current output sequence number.
     * <p>
     * This is the sequence number for the next packet.
     * </p>
     *
     * @return the sequence number as an unsigned 32bit value.
     */
    long getOutputSequenceNumber();

    /**
     * Retrieves the input counters.
     *
     * @return the input counters
     */
    Counters getInputCounters();

    /**
     * Retrieves the output counters.
     *
     * @return the output counters
     */
    Counters getOutputCounters();

    /**
     * Tells whether the connection is secure: encrypted and having a message authentication code, either via an
     * explicit MAC or as part of an AEAD cipher.
     *
     * @return whether the connection is secure
     */
    boolean isSecure();

    /**
     * A collection of connection statistics.
     */
    interface Counters {

        /**
         * Retrieves the number of bytes written (since the last key exchange).
         *
         * @return the number of bytes
         */
        long getBytes();

        /**
         * Retrieves the number of cipher blocks written (since the last key exchange).
         *
         * @return the number of cipher blocks
         */
        long getBlocks();

        /**
         * Retrieves the number of SSH packets written (since the last key exchange).
         *
         * @return the number of packets
         */
        long getPackets();
    }

}
