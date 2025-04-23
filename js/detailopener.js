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

const openDetails = (link) => {
  let detail = link.closest('details');
  while (detail) {
    detail.open = true;
    detail = detail.parentNode;
	if (detail) {
      detail = detail.closest('details');
    }
  }
};

document.addEventListener('click', (e) => {
  // If the target of an internal link is inside a closed "details" section, open the details.
  // Otherwise navigation may not work, and the user has to open the details section manually
  // first, which is a lousy user experience. (Some browsers may open the details automatically,
  // but others, like Firefox, don't.)
  const link = e.target.closest('a');
  if (link) {
    const href = link.getAttribute('href');
    if (href && href.startsWith('#')) {
      const target = document.getElementById(href.substring(1));
      if (target) {
        openDetails(target);
      }
    }
  }
});