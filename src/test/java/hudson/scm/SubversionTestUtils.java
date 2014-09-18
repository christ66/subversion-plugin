package hudson.scm;

import hudson.ClassicPluginStrategy;
import hudson.Launcher.LocalLauncher;
import hudson.Proc;
import hudson.scm.SubversionSCM.DescriptorImpl;
import hudson.util.StreamTaskListener;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import net.sf.json.JSONObject;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.jvnet.hudson.test.HudsonHomeLoader;
import org.jvnet.hudson.test.HudsonHomeLoader.CopyExisting;
import org.jvnet.hudson.test.HudsonTestCase;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestEnvironment;
import org.kohsuke.stapler.StaplerRequest;

import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * Base class for Subversion related tests.
 *
 * @author Kohsuke Kawaguchi
 */
public class SubversionTestUtils {
    public static Proc runSvnServe(URL zip) throws Exception {
      TestEnvironment.get().pin();
      return runSvnServe(new CopyExisting(zip).allocate());
    }

    /**
     * Runs svnserve to serve the specified directory as a subversion repository.
     */
    public static Proc runSvnServe(File repo) throws Exception {
        LocalLauncher launcher = new LocalLauncher(StreamTaskListener.fromStdout());
        try {
            launcher.launch().cmds("svnserve","--help").start().join();
        } catch (IOException e) {
        	Assert.fail("Failed to launch svnserve. Do you have subversion installed?\n" + e);
        }
        return launcher.launch().cmds(
                "svnserve","-d","--foreground","-r",repo.getAbsolutePath()).pwd(repo).start();
    }
}
