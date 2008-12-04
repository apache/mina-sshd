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
package org.apache.sshd.common.mac;

import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.Mac;
import org.apache.sshd.common.util.SecurityUtils;

public class BaseMac implements Mac {

    private final String algorithm;
    private final int defbsize;
    private final int bsize;
    private final byte[] tmp;
    private javax.crypto.Mac mac;

    public BaseMac(String algorithm, int bsize, int defbsize) {
        this.algorithm = algorithm;
        this.bsize = bsize;
        this.defbsize = defbsize;
        this.tmp = new byte[defbsize];
    }

    public int getBlockSize() {
        return bsize;
    }

    public void init(byte[] key) throws Exception {
        if (key.length > defbsize) {
            byte[] tmp = new byte[defbsize];
            System.arraycopy(key, 0, tmp, 0, defbsize);
            key = tmp;
        }

        SecretKeySpec skey = new SecretKeySpec(key, algorithm);
        mac = SecurityUtils.getMac(algorithm);
        mac.init(skey);
    }

    public void update(int i) {
        tmp[0] = (byte) (i >>> 24);
        tmp[1] = (byte) (i >>> 16);
        tmp[2] = (byte) (i >>> 8);
        tmp[3] = (byte) i;
        update(tmp, 0, 4);
    }

    public void update(byte foo[], int s, int l) {
        mac.update(foo, s, l);
    }

    public void doFinal(byte[] buf, int offset) throws Exception {
        if (bsize != defbsize) {
            mac.doFinal(tmp, 0);
            System.arraycopy(tmp, 0, buf, offset, bsize);
        } else {
            mac.doFinal(buf, offset);
        }
    }

}