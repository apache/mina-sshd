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
package org.apache.sshd.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;

import org.apache.sshd.common.util.GenericUtils;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class BaseTest extends TestWatcher {
    @Rule public TestWatcher rule = this;
    @Rule public final TestName TEST_NAME_HOLDER = new TestName();
    private long startTime;

    protected BaseTest() {
    	super();
    }

    public final String getCurrentTestName() {
        return TEST_NAME_HOLDER.getMethodName();
    }

    @Override
    protected void starting(Description description) {
        System.out.println("\nStarting " + description.getClassName() + ":" + description.getMethodName() + "...\n");
        startTime = System.currentTimeMillis();
    }

    @Override
    protected void finished(Description description) {
        long duration = System.currentTimeMillis() - startTime;
        System.out.println("\nFinished " + description.getClassName() + ":" + description.getMethodName() + " in " + duration + " ms\n");
    }

    /* ------------------- Useful extra test helpers ---------------------- */

    public static String shuffleCase(CharSequence cs) {
        if (GenericUtils.isEmpty(cs)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(cs.length());
        for (int index = 0; index < cs.length(); index++) {
            char ch = cs.charAt(index);
            double v = Math.random();
            if (Double.compare(v, 0.3d) < 0) {
                ch = Character.toUpperCase(ch);
            } else if ((Double.compare(v, 0.3d) >= 0) && (Double.compare(v, 0.6d) < 0)) {
                ch = Character.toLowerCase(ch);
            }
            sb.append(ch);
        }

        return sb.toString();
    }

    /* ----------------------- Useful extra assertions --------------------- */

    public static File assertHierarchyTargetFolderExists(File folder) {
        if (!folder.exists()) {
            assertTrue("Failed to create hierarchy of " + folder.getAbsolutePath(), folder.mkdirs());
        }
        
        return folder;
    }
    
    public static void assertObjectInstanceOf(String message, Class<?> expected, Object obj) {
        assertNotNull(message + " - no actual object", obj);
        
        Class<?>    actual=obj.getClass();
        if (!expected.isAssignableFrom(actual)) {
            fail(message + " - actual object type (" + actual.getName() + ") incompatible with expected (" + expected.getName() + ")");
        }
    }
}
