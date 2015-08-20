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
package org.apache.sshd.server.kex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Helper class to load DH group primes from a file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class Moduli {

    public static final int MODULI_TYPE_SAFE = 2;
    public static final int MODULI_TESTS_COMPOSITE = 0x01;

    public static class DhGroup {
        int size;
        BigInteger g;
        BigInteger p;
    }

    // Private constructor
    private Moduli() {
    }

    public static List<DhGroup> parseModuli(URL url) throws IOException {
        List<DhGroup> groups = new ArrayList<DhGroup>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(url.openStream()))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                // Ensure valid line
                if (parts.length != 7) {
                    continue;
                }
                // Discard moduli types which are not safe
                int type = Integer.parseInt(parts[1]);
                if (type != MODULI_TYPE_SAFE) {
                    continue;
                }
                // Discard untested modulis
                int tests = Integer.parseInt(parts[2]);
                if ((tests & MODULI_TESTS_COMPOSITE) != 0 || (tests & ~MODULI_TESTS_COMPOSITE) == 0) {
                    continue;
                }
                // Discard untried
                int tries = Integer.parseInt(parts[3]);
                if (tries == 0) {
                    continue;
                }
                DhGroup group = new DhGroup();
                group.size = Integer.parseInt(parts[4]) + 1;
                group.g = new BigInteger(parts[5], 16);
                group.p = new BigInteger(parts[6], 16);
                groups.add(group);
            }
            return groups;
        }
    }

}
