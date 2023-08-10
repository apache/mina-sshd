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

package org.apache.sshd.contrib.server.session.proxyprotocolv2.utils;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Proxy Utilities class
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
public final class ProxyUtils {

    private ProxyUtils() {
        // Utility Class
    }

    /**
     * Create an hexadecimal string representation of the remaining content of a buffer and reset the buffer after
     * reading.
     *
     * @param  buffer       a buffer to read from
     * @param  markPosition the position from which to start.
     * @return              a hexadecimal string representation.
     */
    public static String toHexString(Buffer buffer, int markPosition) {
        byte[] datas = new byte[buffer.available()];
        buffer.getRawBytes(datas);
        buffer.rpos(markPosition);
        return BufferUtils.toHex(datas, 0, datas.length, ',');
    }
}
