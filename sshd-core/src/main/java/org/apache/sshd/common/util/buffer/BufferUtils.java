/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util.buffer;

import org.apache.sshd.common.util.GenericUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BufferUtils {

    public static String printHex(byte ... array) {
        return printHex(array, 0, GenericUtils.length(array));
    }

    public static String printHex(char sep, byte ... array) {
        return printHex(array, 0, GenericUtils.length(array), sep);
    }

    public static String printHex(byte[] array, int offset, int len) {
        return printHex(array, offset, len, ' ');
    }

    public static final String  HEX_DIGITS="0123456789abcdef";

    public static String printHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder(len * 3 /* 2 HEX + sep */);
        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb.toString();
    }

    public static boolean equals(byte[] a1, byte[] a2) {
        int len1 = GenericUtils.length(a1);
        int len2 = GenericUtils.length(a2);
        if (len1 != len2) {
            return false;
        } else {
            return equals(a1, 0, a2, 0, len1);
        }
    }

    public static boolean equals(byte[] a1, int a1Offset, byte[] a2, int a2Offset, int length) {
        int len1 = GenericUtils.length(a1);
        int len2 = GenericUtils.length(a2);
        if ((len1 < (a1Offset + length)) || (len2 < (a2Offset + length))) {
            return false;
        }

        while (length-- > 0) {
            if (a1[a1Offset++] != a2[a2Offset++]) {
                return false;
            }
        }
        return true;
    }

    public static final int getNextPowerOf2(int i) {
        int j = 1;
        while (j < i) {
            j <<= 1;
        }
        return j;
    }
}
