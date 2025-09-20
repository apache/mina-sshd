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
package org.apache.sshd;

import java.time.Instant;

import org.apache.sshd.util.test.BaseTestSupport;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
public abstract class AbstractContainerTestBase extends BaseTestSupport {

    // Running multiple executions of failsafe with testcontainers appears to run into a problem with
    // containers from previous runs being cleaned up asynchronously while the next execution starts.
    // The next execution then may try to use a parent image that just got removed by the cleanup of the
    // previous execution.
    //
    // Symptom:
    //
    // org.testcontainers.containers.ContainerFetchException: Can't get Docker image: RemoteDockerImage...
    // Caused by:
    // com.github.dockerjava.api.exception.DockerClientException: Could not build image: NotFound: parent snapshot
    // (SHA256) does not exist: not found
    //
    // Try to prevent that by deliberately including a layer that contains a random value.
    private static final String DISCRIMINATOR = "tmp" + Instant.now().toEpochMilli();

    protected AbstractContainerTestBase() {
        super();
    }

    protected static String discriminate() {
        return "touch /" + DISCRIMINATOR;
    }
}
