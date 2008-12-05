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
package org.apache.sshd.common.digest;

import java.security.MessageDigest;

import org.apache.sshd.common.Digest;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class BaseDigest implements Digest {

    private final String algorithm;
    private int bsize;
    private MessageDigest md;

    public BaseDigest(String algorithm, int bsize) {
        this.algorithm = algorithm;
        this.bsize = bsize;
    }

    public int getBlockSize() {
        return bsize;
    }

    public void init() throws Exception {
        this.md = SecurityUtils.getMessageDigest(algorithm);
    }

    public void update(byte[] foo, int start, int len) throws Exception {
        md.update(foo, start, len);
    }

    public byte[] digest() throws Exception {
        return md.digest();
    }

}
