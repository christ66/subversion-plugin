/*
 * The MIT License
 * 
 * Copyright (c) 2014 schristou88
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.scm;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.SVNAuthentication;
import org.tmatesoft.svn.core.internal.wc.DefaultSVNAuthenticationManager;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author schristou88
 */
public class SVNAuthenticationManager extends DefaultSVNAuthenticationManager {
  public SVNAuthenticationManager(File configDir, String userName, String password) {
    super(configDir,
          SVNWCUtil.createDefaultOptions(configDir, true).isAuthStorageEnabled(),
          userName,
          password);
  }

  @Override
  @CheckForNull
  public SVNAuthentication getFirstAuthentication(String kind, String realm, SVNURL url) throws SVNException {
      try {
          return super.getFirstAuthentication(kind, realm, url);
      } catch (SVNException e) {
          LOGGER.log(Level.FINE, "Authentication from default svn location failed. Using credentials.", e);
      }
      
    // SVNKIT DefaultAuthenticationManager ignores any credentials that are added to the manager.
    return super.getAuthenticationProvider().requestClientAuthentication(kind, url, realm, null, null, false);
  }
    
    private static final Logger LOGGER = Logger.getLogger(SVNAuthenticationManager.class.getName());
}
