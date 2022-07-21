package org.opensearch.bootstrap;
/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Disable JarHell to unblock test development
 * https://github.com/opensearch-project/security/issues/1938
 */
public class JarHell {
    private JarHell() {}
    public static void checkJarHell(Consumer<String> output) throws IOException, Exception {}
    public static void checkJarHell(Set<URL> urls, Consumer<String> output) throws URISyntaxException, IOException {}
    public static void checkVersionFormat(String targetVersion) {}
    public static void checkJavaVersion(String resource, String targetVersion) {}
    public static Set<URL> parseClassPath() {return new HashSet<URL>();}
}