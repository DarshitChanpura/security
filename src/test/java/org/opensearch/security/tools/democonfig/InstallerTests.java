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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.tools.democonfig.Installer.BASE_DIR;
import static org.opensearch.security.tools.democonfig.Installer.FILE_EXTENSION;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_BIN_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_FILE;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_INSTALL_TYPE;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_LIB_PATH;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_PLUGINS_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_VERSION;
import static org.opensearch.security.tools.democonfig.Installer.OS;
import static org.opensearch.security.tools.democonfig.Installer.RPM_DEB_OPENSEARCH_FILE;
import static org.opensearch.security.tools.democonfig.Installer.SCRIPT_DIR;
import static org.opensearch.security.tools.democonfig.Installer.SECURITY_VERSION;
import static org.opensearch.security.tools.democonfig.Installer.assumeyes;
import static org.opensearch.security.tools.democonfig.Installer.cluster_mode;
import static org.opensearch.security.tools.democonfig.Installer.determineInstallType;
import static org.opensearch.security.tools.democonfig.Installer.environment;
import static org.opensearch.security.tools.democonfig.Installer.finishScriptExecution;
import static org.opensearch.security.tools.democonfig.Installer.gatherUserInputs;
import static org.opensearch.security.tools.democonfig.Installer.initializeVariables;
import static org.opensearch.security.tools.democonfig.Installer.initsecurity;
import static org.opensearch.security.tools.democonfig.Installer.printScriptHeaders;
import static org.opensearch.security.tools.democonfig.Installer.printVariables;
import static org.opensearch.security.tools.democonfig.Installer.readOptions;
import static org.opensearch.security.tools.democonfig.Installer.resetState;
import static org.opensearch.security.tools.democonfig.Installer.setBaseDir;
import static org.opensearch.security.tools.democonfig.Installer.setOpenSearchVariables;
import static org.opensearch.security.tools.democonfig.Installer.setSecurityVariables;
import static org.opensearch.security.tools.democonfig.Installer.skip_updates;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

public class InstallerTests extends SingleClusterTest {
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    @Before
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
        resetState();
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setIn(originalIn);
    }

    @Test
    public void testPrintScriptHeaders() {
        printScriptHeaders();

        String expectedOutput = "### OpenSearch Security Demo Installer\n"
            + "### ** Warning: Do not use on production or public reachable systems **\n";
        assertThat(expectedOutput, equalTo(outContent.toString()));
    }

    @Test
    public void testReadOptions_withoutHelpOption() {
        // All options except Help `-h`
        String[] validOptions = { "/scriptDir", "-y", "-i", "-c", "-s", "-t" };
        readOptions(validOptions);

        assertEquals("/scriptDir", SCRIPT_DIR);
        assertThat(assumeyes, is(true));
        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
        assertEquals(0, skip_updates);
        assertEquals(ExecutionEnvironment.TEST, environment);
    }

    @Test
    public void testReadOptions_help() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            String[] helpOption = { "/scriptDir", "-h" };
            readOptions(helpOption);

            assertThat(outContent.toString(), containsString("install_demo_configuration.sh [-y] [-i] [-c]"));
            assertThat(outContent.toString(), containsString("-h show help"));
            assertThat(outContent.toString(), containsString("-y confirm all installation dialogues automatically"));
            assertThat(outContent.toString(), containsString("-i initialize Security plugin with default configuration"));
            assertThat(outContent.toString(), containsString("-c enable cluster mode by binding to all network interfaces"));
            assertThat(outContent.toString(), containsString("-s skip updates if config is already applied to opensearch.yml"));
            assertThat(outContent.toString(), containsString("-t set the execution environment to `test` to skip password validation"));
            assertThat(outContent.toString(), containsString("Should be used only for testing. (default is set to `demo`)"));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testGatherUserInputs_withoutAssumeYes() {
        // -i & -c option is not passed
        String[] validOptions = { "/scriptDir" };
        readOptions(validOptions);
        assertThat(assumeyes, is(false));
        assertThat(initsecurity, is(false));
        assertThat(cluster_mode, is(false));

        // set initsecurity and cluster_mode to no
        readInputStream("y\nn\nn\n"); // pass all 3 inputs as y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), containsString("Initialize Security Modules?"));
        assertThat(outContent.toString(), containsString("Cluster mode requires additional setup of:"));
        assertThat(outContent.toString(), containsString("  - Virtual memory (vm.max_map_count)\n"));
        assertThat(outContent.toString(), containsString("Enable cluster mode?"));

        assertThat(initsecurity, is(false));
        assertThat(cluster_mode, is(false));

        outContent.reset();

        // set initsecurity and cluster_mode to no
        readInputStream("y\ny\ny\n"); // pass all 3 inputs as y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), containsString("Initialize Security Modules?"));
        assertThat(outContent.toString(), containsString("Cluster mode requires additional setup of:"));
        assertThat(outContent.toString(), containsString("  - Virtual memory (vm.max_map_count)\n"));
        assertThat(outContent.toString(), containsString("Enable cluster mode?"));

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));

        outContent.reset();

        // no to demo certificates
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            readInputStream("n\nn\nn\n");
            gatherUserInputs();

            assertThat(outContent.toString(), containsString("Install demo certificates?"));
            assertThat(outContent.toString(), not(containsString("Initialize Security Modules?")));
            assertThat(outContent.toString(), not(containsString("Cluster mode requires additional setup of:")));
            assertThat(outContent.toString(), not(containsString("  - Virtual memory (vm.max_map_count)\n")));
            assertThat(outContent.toString(), not(containsString("Enable cluster mode?")));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        outContent.reset();

        // pass initsecurity and cluster_mode options
        String[] validOptionsIC = { "/scriptDir", "-i", "-c" };
        readOptions(validOptionsIC);
        assertThat(assumeyes, is(false));
        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));

        readInputStream("y\ny\ny\n"); // pass all 3 inputs as y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), not(containsString("Initialize Security Modules?")));
        assertThat(outContent.toString(), not(containsString("Enable cluster mode?")));

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
    }

    @Test
    public void testGatherInputs_withAssumeYes() {
        String[] validOptionsYes = { "/scriptDir", "-y" };
        readOptions(validOptionsYes);
        assertThat(assumeyes, is(true));

        gatherUserInputs();

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
    }

    @Test
    public void testInitializeVariables_setBaseDir_invalidPath() {
        String[] invalidScriptDirPath = { "/scriptDir", "-y" };
        readOptions(invalidScriptDirPath);

        assertThrows("Expected NullPointerException to be thrown", NullPointerException.class, Installer::initializeVariables);

        resetState();

        String[] invalidScriptDirPath2 = { "/opensearch/plugins/opensearch-security/tools", "-y" };
        readOptions(invalidScriptDirPath2);

        try {
            System.setSecurityManager(new NoExitSecurityManager());

            initializeVariables();
            assertThat(outContent.toString(), containsString("DEBUG: basedir does not exist"));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testSetBaseDir_valid() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);

        setBaseDir();

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        assertThat(BASE_DIR, equalTo(expectedBaseDirValue));
    }

    @Test
    public void testSetOpenSearchVariables_invalidPath() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);

        try {
            System.setSecurityManager(new NoExitSecurityManager());

            setBaseDir();
            setOpenSearchVariables();

            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch config file. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch bin directory. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch plugins directory. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch lib directory. Quit."));

        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        String expectedOpensearchConfFilePath = expectedBaseDirValue + "config" + File.separator + "opensearch.yml";
        String expectedOpensearchBinDirPath = expectedBaseDirValue + "bin" + File.separator;
        String expectedOpensearchPluginDirPath = expectedBaseDirValue + "plugins" + File.separator;
        String expectedOpensearchLibDirPath = expectedBaseDirValue + "lib" + File.separator;
        String expectedOpensearchInstallType = determineInstallType();

        assertThat(OPENSEARCH_CONF_FILE, equalTo(expectedOpensearchConfFilePath));
        assertThat(OPENSEARCH_BIN_DIR, equalTo(expectedOpensearchBinDirPath));
        assertThat(OPENSEARCH_PLUGINS_DIR, equalTo(expectedOpensearchPluginDirPath));
        assertThat(OPENSEARCH_LIB_PATH, equalTo(expectedOpensearchLibDirPath));
        assertThat(OPENSEARCH_INSTALL_TYPE, equalTo(expectedOpensearchInstallType));

    }

    @Test
    public void testDetermineInstallType_windows() {
        OS = "Windows";

        String installType = determineInstallType();

        assertEquals(".zip", installType);
    }

    @Test
    public void testDetermineInstallType_rpm_deb() {
        OS = "Linux";
        String dir = System.getProperty("user.dir");
        BASE_DIR = dir;
        RPM_DEB_OPENSEARCH_FILE = new File(dir);

        String installType = determineInstallType();

        assertEquals("rpm/deb", installType);
    }

    @Test
    public void testDetermineInstallType_default() {
        OS = "Anything else";
        BASE_DIR = "/random-dir";
        String installType = determineInstallType();

        assertEquals(".tar.gz", installType);
    }

    @Test
    public void testSetSecurityVariables() {
        setUpSecurityDirectories();
        setSecurityVariables();

        assertThat(OPENSEARCH_VERSION, is(equalTo("osVersion")));
        assertThat(SECURITY_VERSION, is(equalTo("version")));
        tearDownSecurityDirectories();
    }

    @Test
    public void testSetSecurityVariables_noSecurityPlugin() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            setSecurityVariables();
            fail("Expected System.exit(-1) to be called");
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testPrintVariables() {
        OPENSEARCH_INSTALL_TYPE = "installType";
        OS = "OS";
        OPENSEARCH_CONF_DIR = "confDir";
        OPENSEARCH_CONF_FILE = "confFile";
        OPENSEARCH_BIN_DIR = "/bin";
        OPENSEARCH_PLUGINS_DIR = "/plugins";
        OPENSEARCH_LIB_PATH = "/lib";
        OPENSEARCH_VERSION = "osVersion";
        SECURITY_VERSION = "version";

        printVariables();

        String expectedOutput = "OpenSearch install type: installType on OS\n"
            + "OpenSearch config dir: confDir\n"
            + "OpenSearch config file: confFile\n"
            + "OpenSearch bin dir: /bin\n"
            + "OpenSearch plugins dir: /plugins\n"
            + "OpenSearch lib dir: /lib\n"
            + "Detected OpenSearch Version: osVersion\n"
            + "Detected OpenSearch Security Version: version\n";

        assertEquals(expectedOutput, outContent.toString());
    }

    @Test
    public void testFinishScriptExecution() {
        setUpSecurityDirectories();
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        finishScriptExecution();

        String securityAdminScriptPath = OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + FILE_EXTENSION;
        String securityAdminDemoScriptPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        String lastLine = SecuritySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];
        // Verify the expected output
        String expectedOutput = "### Success\n"
            + "### Execute this script now on all your nodes and then start all nodes\n"
            + "### After the whole cluster is up execute: \n"
            + lastLine
            + "\n"
            + "### or run ."
            + File.separator
            + "securityadmin_demo.sh\n"
            + "### After that you can also use the Security Plugin ConfigurationGUI\n"
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/"
            + SecuritySettingsConfigurer.ADMIN_PASSWORD
            + ".\n"
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)\n";

        assertEquals(expectedOutput, outContent.toString());

        tearDownSecurityDirectories();
    }

    @Test
    public void testFinishScriptExecution_withInitSecurityEnabled() {
        setUpSecurityDirectories();
        initsecurity = true;
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        finishScriptExecution();

        String securityAdminScriptPath = OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + FILE_EXTENSION;
        String securityAdminDemoScriptPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        String lastLine = SecuritySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];
        String expectedOutput = "### Success\n"
            + "### Execute this script now on all your nodes and then start all nodes\n"
            + "### OpenSearch Security will be automatically initialized.\n"
            + "### If you like to change the runtime configuration \n"
            + "### change the files in .."
            + File.separator
            + ".."
            + File.separator
            + ".."
            + File.separator
            + "config"
            + File.separator
            + "opensearch-security and execute: \n"
            + lastLine
            + "\n"
            + "### or run ."
            + File.separator
            + "securityadmin_demo.sh\n"
            + "### To use the Security Plugin ConfigurationGUI\n"
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/"
            + SecuritySettingsConfigurer.ADMIN_PASSWORD
            + ".\n"
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)\n";

        assertEquals(expectedOutput, outContent.toString());

        tearDownSecurityDirectories();
    }

    private void readInputStream(String input) {
        System.setIn(new ByteArrayInputStream(input.getBytes()));
    }

    public void setUpSecurityDirectories() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);
        setBaseDir();
        OPENSEARCH_PLUGINS_DIR = BASE_DIR + "plugins" + File.separator;
        OPENSEARCH_LIB_PATH = BASE_DIR + "lib" + File.separator;
        OPENSEARCH_CONF_DIR = BASE_DIR + "test-conf" + File.separator;

        createDirectory(OPENSEARCH_PLUGINS_DIR);
        createDirectory(OPENSEARCH_LIB_PATH);
        createDirectory(OPENSEARCH_CONF_DIR);
        createDirectory(OPENSEARCH_PLUGINS_DIR + "opensearch-security");
        createFile(OPENSEARCH_LIB_PATH + "opensearch-osVersion.jar");
        createFile(OPENSEARCH_PLUGINS_DIR + "opensearch-security" + File.separator + "opensearch-security-version.jar");
        createFile(OPENSEARCH_CONF_DIR + File.separator + "securityadmin_demo.sh");
    }

    public void tearDownSecurityDirectories() {
        // Clean up testing directories or files
        deleteFile(OPENSEARCH_PLUGINS_DIR + "opensearch-security" + File.separator + "opensearch-security-version.jar");
        deleteFile(OPENSEARCH_LIB_PATH + "opensearch-osVersion.jar");
        deleteDirectory(OPENSEARCH_PLUGINS_DIR + "opensearch-security");
        deleteDirectory(OPENSEARCH_PLUGINS_DIR);
        deleteDirectory(OPENSEARCH_LIB_PATH);
        deleteFile(OPENSEARCH_CONF_DIR + File.separator + "securityadmin_demo.sh");
        deleteDirectory(OPENSEARCH_CONF_DIR);
    }

    private void createDirectory(String path) {
        File directory = new File(path);
        if (!directory.exists() && !directory.mkdirs()) {
            throw new RuntimeException("Failed to create directory: " + path);
        }
    }

    private void createFile(String path) {
        try {
            File file = new File(path);
            if (!file.exists() && !file.createNewFile()) {
                throw new RuntimeException("Failed to create file: " + path);
            }
        } catch (Exception e) {
            // without this the catch, we would need to throw exception,
            // which would then require modifying caller method signature
            throw new RuntimeException("Failed to create file: " + path, e);
        }
    }

    private void deleteDirectory(String path) {
        File directory = new File(path);
        if (directory.exists() && !directory.delete()) {
            throw new RuntimeException("Failed to delete directory: " + path);
        }
    }

    private void deleteFile(String path) {
        File file = new File(path);
        if (file.exists() && !file.delete()) {
            throw new RuntimeException("Failed to delete file: " + path);
        }
    }

    private void setWritePermissions(String filePath) {
        if (!OS.toLowerCase().contains("win")) {
            Path file = Paths.get(filePath);
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_WRITE);
            try {
                Files.setPosixFilePermissions(file, perms);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

}

class NoExitSecurityManager extends SecurityManager {
    @Override
    public void checkPermission(java.security.Permission perm) {
        // Allow everything except System.exit code 0 &b -1
        if (perm instanceof java.lang.RuntimePermission && ("exitVM.0".equals(perm.getName()) || "exitVM.-1".equals(perm.getName()))) {
            StringBuilder sb = new StringBuilder();
            sb.append("System.exit(");
            sb.append(perm.getName().contains("0") ? 0 : -1);
            sb.append(") blocked to allow print statement testing.");
            throw new SecurityException(sb.toString());
        }
    }
}
