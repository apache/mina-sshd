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

log.info("Including japicmp reports in the site")

def reports = new File("${project.build.directory}/src/site/markdown").listFiles()
def names = []

reports.each() { file ->
  names.add(file.name)
}

def site = new File("${project.build.directory}/src/site/site.xml")
def siteContent = site.text

names.sort().each() { name ->
  if (name.startsWith("japicmp-")) {
    log.info("Adding ${name}")
    def page = name.substring(0, name.size() - 3)
    def module = page.substring(8)
    siteContent = siteContent.replaceFirst("<!-- JAPICMP -->", "<item href=\"${page}.html\" name=\"${module}\" />\n<!-- JAPICMP -->")
  }
}

site.text = siteContent

reports.each() { file ->
  def name = file.name
  if (name.startsWith("japicmp-")) {
    log.info("Removing generation timestamp from ${name}")
    def content = file.text
    file.text = content.replaceFirst("___\\R\\R\\*Generated on[^\n\r]*", "")
  }
}
