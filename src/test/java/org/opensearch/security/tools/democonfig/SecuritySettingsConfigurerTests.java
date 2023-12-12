/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.tools.democonfig;

// CS-SUPPRESS-SINGLE: RegexpSingleline extension key-word is used in file ext variable
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.REST_ENABLED_ROLES;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.SYSTEM_INDICES;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.isKeyPresentInYMLFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public class SecuritySettingsConfigurerTests {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    private final String adminPasswordKey = "initialAdminPassword";

    private static SecuritySettingsConfigurer securitySettingsConfigurer;

    private static Installer installer;

    @Before
    public void setUp() {
        System.setOut(new PrintStream(outContent));
        installer = Installer.getInstance();
        installer.buildOptions();
        securitySettingsConfigurer = new SecuritySettingsConfigurer(installer);
        setUpConf();
    }

    @After
    public void tearDown() throws NoSuchFieldException, IllegalAccessException {
        System.setOut(originalOut);
        System.setIn(originalIn);
        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR);
        unsetEnv(adminPasswordKey);
        Installer.resetInstance();
    }

    @Test
    public void testUpdateAdminPasswordWithCustomPassword() throws NoSuchFieldException, IllegalAccessException {
        String customPassword = "myStrongPassword123"; // generateStrongPassword();
        setEnv(adminPasswordKey, customPassword);

        securitySettingsConfigurer.updateAdminPassword();

        assertThat(customPassword, is(equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD)));

        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: " + customPassword));
    }

    @Test
    public void testUpdateAdminPasswordWithFilePassword() throws IOException {
        String customPassword = "myStrongPassword123";
        String initialAdminPasswordTxt = installer.OPENSEARCH_CONF_DIR + adminPasswordKey + ".txt";
        createFile(initialAdminPasswordTxt);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(initialAdminPasswordTxt, StandardCharsets.UTF_8))) {
            writer.write(customPassword);
        } catch (IOException e) {
            throw new IOException("Unable to update the internal users file with the hashed password.");
        }

        securitySettingsConfigurer.updateAdminPassword();

        assertEquals(customPassword, SecuritySettingsConfigurer.ADMIN_PASSWORD);
        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: " + customPassword));
    }

    @Test
    public void testUpdateAdminPassword_noPasswordSupplied() {
        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR); // to ensure no flakiness
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            securitySettingsConfigurer.updateAdminPassword();
            assertThat(outContent.toString(), containsString("No custom admin password found. Please provide a password."));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword() throws NoSuchFieldException, IllegalAccessException {

        setEnv(adminPasswordKey, "weakpassword");
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            securitySettingsConfigurer.updateAdminPassword();

            assertThat(outContent.toString(), containsString("Password weakpassword is weak. Please re-try with a stronger password."));

        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword_skipPasswordValidation() throws NoSuchFieldException, IllegalAccessException {
        setEnv(adminPasswordKey, "weakpassword");
        installer.environment = ExecutionEnvironment.TEST;
        securitySettingsConfigurer.updateAdminPassword();

        assertThat("weakpassword", is(equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD)));
        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: weakpassword"));
    }

    @Test
    public void testSecurityPluginAlreadyConfigured() {
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            String expectedMessage = installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.";

            securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
            assertThat(outContent.toString(), containsString(expectedMessage));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testSecurityPluginNotConfigured() {
        try {
            securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
        } catch (Exception e) {
            fail("Expected checkIfSecurityPluginIsAlreadyConfigured to succeed without any errors.");
        }
    }

    @Test
    public void testConfigFileDoesNotExist() {
        installer.OPENSEARCH_CONF_FILE = "path/to/nonexistentfile";
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            String expectedMessage = "OpenSearch configuration file does not exist. Quit.";

            securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
            assertThat(outContent.toString(), containsString(expectedMessage));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
        // reset the file pointer
        installer.OPENSEARCH_CONF_FILE = installer.OPENSEARCH_CONF_DIR + "opensearch.yml";
    }

    @Test
    public void testBuildSecurityConfigMap() {
        Map<String, Object> actual = securitySettingsConfigurer.buildSecurityConfigMap();

        assertThat(actual.size(), is(17));
        assertThat(actual.get("plugins.security.ssl.transport.pemcert_filepath"), is(equalTo(Certificates.NODE_CERT.getFileName())));
        assertThat(actual.get("plugins.security.ssl.transport.pemkey_filepath"), is(equalTo(Certificates.NODE_KEY.getFileName())));
        assertThat(actual.get("plugins.security.ssl.transport.pemtrustedcas_filepath"), is(equalTo(Certificates.ROOT_CA.getFileName())));
        assertThat(actual.get("plugins.security.ssl.transport.enforce_hostname_verification"), is(equalTo(false)));
        assertThat(actual.get("plugins.security.ssl.http.enabled"), is(equalTo(true)));
        assertThat(actual.get("plugins.security.ssl.http.pemcert_filepath"), is(equalTo(Certificates.NODE_CERT.getFileName())));
        assertThat(actual.get("plugins.security.ssl.http.pemkey_filepath"), is(equalTo(Certificates.NODE_KEY.getFileName())));
        assertThat(actual.get("plugins.security.ssl.http.pemtrustedcas_filepath"), is(equalTo(Certificates.ROOT_CA.getFileName())));
        assertThat(actual.get("plugins.security.allow_unsafe_democertificates"), is(equalTo(true)));
        assertThat(actual.get("plugins.security.authcz.admin_dn"), is(equalTo(List.of("CN=kirk,OU=client,O=client,L=test,C=de"))));
        assertThat(actual.get("plugins.security.audit.type"), is(equalTo("internal_opensearch")));
        assertThat(actual.get("plugins.security.enable_snapshot_restore_privilege"), is(equalTo(true)));
        assertThat(actual.get("plugins.security.check_snapshot_restore_write_privileges"), is(equalTo(true)));
        assertThat(actual.get("plugins.security.restapi.roles_enabled"), is(equalTo(REST_ENABLED_ROLES)));
        assertThat(actual.get("plugins.security.system_indices.enabled"), is(equalTo(true)));
        assertThat(actual.get("plugins.security.system_indices.indices"), is(equalTo(SYSTEM_INDICES)));
        assertThat(actual.get("node.max_local_storage_nodes"), is(equalTo(3)));

        installer.initsecurity = true;
        actual = securitySettingsConfigurer.buildSecurityConfigMap();
        assertThat(actual.get("plugins.security.allow_default_init_securityindex"), is(equalTo(true)));

        installer.cluster_mode = true;
        actual = securitySettingsConfigurer.buildSecurityConfigMap();
        assertThat(actual.get("network.host"), is(equalTo("0.0.0.0")));
        assertThat(actual.get("node.name"), is(equalTo("smoketestnode")));
        assertThat(actual.get("cluster.initial_cluster_manager_nodes"), is(equalTo("smoketestnode")));
    }

    @Test
    public void testIsStringAlreadyPresentInFile_isNotPresent() throws IOException {
        String str1 = "network.host";
        String str2 = "some.random.config";

        installer.initsecurity = true;
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();

        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str1), is(equalTo(false)));
        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str2), is(equalTo(false)));
    }

    @Test
    public void testIsStringAlreadyPresentInFile_isPresent() throws IOException {
        String str1 = "network.host";
        String str2 = "some.random.config";

        installer.initsecurity = true;
        installer.cluster_mode = true;
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();

        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str1), is(equalTo(true)));
        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str2), is(equalTo(false)));
    }

    @Test
    public void testCreateSecurityAdminDemoScriptAndGetSecurityAdminCommands() throws IOException {
        String demoPath = installer.OPENSEARCH_CONF_DIR + "securityadmin_demo" + installer.FILE_EXTENSION;
        securitySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);

        assertThat(new File(demoPath).exists(), is(equalTo(true)));

        String[] commands = securitySettingsConfigurer.getSecurityAdminCommands("scriptPath");

        try (BufferedReader reader = new BufferedReader(new FileReader(demoPath, StandardCharsets.UTF_8))) {
            assertThat(reader.readLine(), is(commands[0]));
            assertThat(reader.readLine(), is(equalTo(commands[1])));
        }
    }

    @Test
    public void testCreateSecurityAdminDemoScript_invalidPath() {
        String demoPath = null;
        try {
            securitySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);
            fail("Expected to throw Exception");
        } catch (IOException | NullPointerException e) {
            // expected
        }
    }

    @SuppressWarnings("unchecked")
    public static void setEnv(String key, String value) throws NoSuchFieldException, IllegalAccessException {
        Class<?>[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (Class<?> cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                Map<String, String> map = (Map<String, String>) obj;
                map.clear();
                map.put(key, value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static void unsetEnv(String key) throws NoSuchFieldException, IllegalAccessException {
        Class<?>[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (Class<?> cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                Map<String, String> map = (Map<String, String>) obj;
                map.remove(key);
            }
        }
    }

    void setUpConf() {
        installer.OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf" + File.separator;
        installer.OPENSEARCH_CONF_FILE = installer.OPENSEARCH_CONF_DIR + "opensearch.yml";
        String securityConfDir = installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator;
        createDirectory(securityConfDir);
        createFile(securityConfDir + "internal_users.yml");
        createFile(installer.OPENSEARCH_CONF_FILE);
    }
}
