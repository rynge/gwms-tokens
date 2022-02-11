#!/bin/bash
set -e
yum -y install patch python2-scitokens
yum -y upgrade ca-certificates osg-ca-certs
# GIT: cb06dc0b Ready for release v3_9_3
# Use git diff in the glideinwms checkout to generate the patch
pushd /usr/lib/python3.6/site-packages/glideinwms
patch -p1 <<'__END_PATCH__'
 frontend/glideinFrontendElement.py | 215 ++++++++++++++++++++-----------------
 1 file changed, 118 insertions(+), 97 deletions(-)

diff --git a/frontend/glideinFrontendElement.py b/frontend/glideinFrontendElement.py
index 7277570a..3c5ae6d4 100755
--- a/frontend/glideinFrontendElement.py
+++ b/frontend/glideinFrontendElement.py
@@ -804,35 +804,13 @@ class glideinFrontendElement:
                     logSupport.log.debug("found condor token: %s" % entry_token_name)
                     gp_encrypt[entry_token_name] = ctkn
                 # now see if theres a scitoken for this site
-                scitoken_fullpath = ''
-                cred_type_data = self.elementDescript.element_data.get('ProxyTypes')
-                trust_domain_data = self.elementDescript.element_data.get('ProxyTrustDomains')
-                if not cred_type_data:
-                    cred_type_data = self.elementDescript.frontend_data.get('ProxyTypes')
-                if not trust_domain_data:
-                    trust_domain_data = self.elementDescript.frontend_data.get('ProxyTrustDomains')
-                if trust_domain_data and cred_type_data:
-                    cred_type_map = eval(cred_type_data)
-                    trust_domain_map = eval(trust_domain_data)
-                    for cfname in cred_type_map:
-                        if cred_type_map[cfname] == 'scitoken':
-                            if trust_domain_map[cfname] == trust_domain:
-                                scitoken_fullpath = cfname
-                    
-                if os.path.exists(scitoken_fullpath):
-                    try:
-                        logSupport.log.info('found scitoken %s' % scitoken_fullpath)
-                        with open(scitoken_fullpath,'r') as fbuf:
-                            for line in fbuf:
-                                stkn += line
-                        if stkn:
-                            gp_encrypt['frontend_scitoken'] =  stkn
-                    except Exception as err:
-                        logSupport.log.exception("failed to read scitoken: %s" % err)
-
+                if self.scitoken_ok(glidein_el['attrs'].get('GLIDEIN_Gatekeeper')):
+                    stkn = self.refresh_entry_scitoken(glidein_el)
+                    if stkn:
+                        gp_encrypt['frontend_scitoken'] =  stkn
 
                 # now advertise
-                logSupport.log.info('advertising tokens %s' % gp_encrypt.keys())
+                logSupport.log.debug('advertising tokens %s' % list(gp_encrypt.keys()))
                 advertizer.add(factory_pool_node,
                            request_name, request_name,
                            glidein_min_idle,
@@ -900,88 +878,131 @@ class glideinFrontendElement:
 
         return
 
-    def refresh_entry_token(self, glidein_el):
+
+    scitoken_allow_last_read = 0
+    scitoken_allow = []
+    def scitoken_ok(self, gatekeeper):
         """
-            create or update a condor token for an entry point
+            check the resource name against our list of tested scitoken sites
+        """
+
+        now = time.time()
+        if self.scitoken_allow_last_read is None or self.scitoken_allow_last_read < (now - 300):
+            logSupport.log.debug("Re-reading /var/lib/gwms-frontend/web-area/scitoken-testing/allow.txt")
+            self.scitoken_allow_last_read = now
+            with open('/var/lib/gwms-frontend/web-area/scitoken-testing/allow.txt', 'r') as f:
+                self.scitoken_allow = [line.strip() for line in f]
+
+        gk_simple = re.sub(' .*', '', gatekeeper)
+        return (gk_simple in self.scitoken_allow)
+
+
+    def refresh_entry_scitoken(self, glidein_el):
+        """
+            create or update a scitoken for an entry point
             params:  glidein_el: a glidein element data structure
-            returns:  jwt encoded condor token on success
+            returns:  jwt encoded token on success
                       None on failure
         """
         tkn_file = ''
         tkn_str = ''
         tmpnm = ''
-        # does condor version of entry point support condor token auth
-        condor_version = glidein_el['params'].get('CONDOR_VERSION')
-        if condor_version:
-            try:
-                # create a condor token named for entry point site name
-                glidein_site = glidein_el['attrs']['GLIDEIN_Site']
-                #tkn_file = "/var/lib/gwms-frontend/.condor/tokens.d/"
-                #tkn_file += glidein_site
-                #tkn_file += ".token"
-                #cmd = "/usr/sbin/frontend_condortoken %s" % glidein_site
-                #tkn_str = subprocessSupport.iexe_cmd(cmd, useShell=True)
-                #os.chmod(tmpnm, 0o600)
-                #os.write(fd, tkn_str)
-                #os.close(fd)
-                #shutil.move(tmpnm, tkn_file)
-                #file_tmp2final(tkn_file, tmpnm)
-                #os.chmod(tkn_file, 0o600)
-                #logSupport.log.debug("created token %s" % tkn_file)
-                tkn_dir = "/var/lib/gwms-frontend/tokens.d"
-                pwd_dir = "/var/lib/gwms-frontend/passwords.d"
-                req_dir = "/var/lib/gwms-frontend/passwords.d/requests"
-                if not os.path.exists(tkn_dir):
-                    os.mkdir(tkn_dir,0o700)
-                if not os.path.exists(pwd_dir):
-                    os.mkdir(pwd_dir,0o700)
-                if not os.path.exists(req_dir):
-                    os.mkdir(req_dir,0o700)
-                tkn_file = tkn_dir + '/' + glidein_site + ".idtoken"
-                pwd_file = pwd_dir + '/' + glidein_site
-                pwd_default = pwd_dir + '/' + 'FRONTEND'
-                req_file = req_dir + '/' + glidein_site
-                one_hr = 3600
-                tkn_age = sys.maxsize
-                if not os.path.exists(pwd_file):
-                    if os.path.exists(pwd_default):
-                        pwd_file = pwd_default
-                if os.path.exists(tkn_file):
-                    tkn_age = time.time() - os.stat(tkn_file).st_mtime
-                if tkn_age > one_hr and os.path.exists(pwd_file):    
-                    #TODO: scope, duration, identity  should be configurable from frontend.xml
-                    (fd, tmpnm) = tempfile.mkstemp()
-                    scope = "condor:/READ condor:/ADVERTISE_STARTD condor:/ADVERTISE_MASTER"
-                    duration = 24 * one_hr
-                    identity = "vofrontend_service@%s" % socket.gethostname()
-                    logSupport.log.debug("creating  token %s" % tkn_file)
-                    logSupport.log.debug("pwd_flie= %s" % pwd_file)
-                    logSupport.log.debug("scope= %s" % scope)
-                    logSupport.log.debug("duration= %s" % duration)
-                    logSupport.log.debug("identity= %s" % identity)
-                    tkn_str = token_util.create_and_sign_token(pwd_file,
-                                                               scope=scope,
-                                                               duration=duration,
-                                                               identity=identity)
-                    #cmd = "/usr/sbin/frontend_condortoken %s" % glidein_site
-                    #tkn_str = subprocessSupport.iexe_cmd(cmd, useShell=True)
-                    logSupport.log.debug("tkn_str= %s" % tkn_str)
-                    os.write(fd, tkn_str)
-                    os.close(fd)
-                    shutil.move(tmpnm, tkn_file)
-                    os.chmod(tkn_file, 0o600)
-                    logSupport.log.info("created token %s" % tkn_file)
-                elif os.path.exists(tkn_file):
-                    with open(tkn_file, 'r') as fbuf:
-                        for line in fbuf:
-                            tkn_str += line
-            except Exception as err:
+        logSupport.log.debug("Checking for scitoken refresh of %s." % glidein_el['attrs'].get('EntryName', '(unknown)'))
+        try:
+            # create a condor token named for entry name
+            glidein_site = glidein_el['attrs']['GLIDEIN_Site']; entry_name = glidein_el['attrs']['EntryName']
+            gatekeeper = glidein_el['attrs'].get('GLIDEIN_Gatekeeper')
+            audience = None
+            if gatekeeper:
+                audience = gatekeeper.split()[-1]
+            tkn_dir = "/var/lib/gwms-frontend/tokens.d"
+            if not os.path.exists(tkn_dir):
+                os.mkdir(tkn_dir,0o700)
+            tkn_file = tkn_dir + '/' +  entry_name + ".scitoken"
+            one_hr = 3600
+            tkn_age = sys.maxsize
+            if os.path.exists(tkn_file):
+                tkn_age = time.time() - os.stat(tkn_file).st_mtime
+            if tkn_age > one_hr:    
+                (fd, tmpnm) = tempfile.mkstemp()
+                cmd = "/usr/sbin/frontend_scitoken %s %s" % (audience, glidein_site)
+                tkn_str = subprocessSupport.iexe_cmd(cmd)
+                os.write(fd, tkn_str.encode('utf-8'))
+                os.close(fd)
+                shutil.move(tmpnm, tkn_file)
+                os.chmod(tkn_file, 0o600)
+                logSupport.log.debug("created token %s" % tkn_file)
+            elif os.path.exists(tkn_file):
+                with open(tkn_file, 'r') as fbuf:
+                    for line in fbuf:
+                        tkn_str += line
+        except Exception as err:
                 logSupport.log.warning('failed to create %s' % tkn_file)
                 for i in sys.exc_info():
                     logSupport.log.warning('%s' % i)
-            finally:
+        finally:
                 if os.path.exists(tmpnm):
                     os.remove(tmpnm)
+        # the factory does not like white spaces
+        tkn_str = tkn_str.strip()
+        return tkn_str
+
+
+    def refresh_entry_token(self, glidein_el):
+        """
+            create or update a condor token for an entry point
+            params:  glidein_el: a glidein element data structure
+            returns:  jwt encoded condor token on success
+                      None on failure
+        """
+        tkn_file = ''
+        tkn_str = ''
+        tmpnm = ''
+        try:
+            # create a condor token named for entry name
+            entry_name = glidein_el['attrs']['EntryName']
+            tkn_dir = "/var/lib/gwms-frontend/tokens.d"
+            pwd_dir = "/var/lib/gwms-frontend/passwords.d"
+            req_dir = "/var/lib/gwms-frontend/passwords.d/requests"
+            if not os.path.exists(tkn_dir):
+                os.mkdir(tkn_dir,0o700)
+            if not os.path.exists(pwd_dir):
+                os.mkdir(pwd_dir,0o700)
+            if not os.path.exists(req_dir):
+                os.mkdir(req_dir,0o700)
+            tkn_file = tkn_dir + '/' + entry_name + ".idtoken"
+            pwd_file = pwd_dir + '/' + entry_name
+            pwd_default = pwd_dir + '/' + 'FRONTEND'
+            req_file = req_dir + '/' + entry_name
+            one_hr = 3600
+            tkn_age = sys.maxsize
+            if not os.path.exists(pwd_file):
+                if os.path.exists(pwd_default):
+                    pwd_file = pwd_default
+            if os.path.exists(tkn_file):
+                tkn_age = time.time() - os.stat(tkn_file).st_mtime
+            if tkn_age > one_hr and os.path.exists(pwd_file):    
+                #TODO: scope, duration, identity  should be configurable from frontend.xml
+                (fd, tmpnm) = tempfile.mkstemp()
+                logSupport.log.debug("Refreshing %s idtoken by calling /usr/sbin/frontend_idtoken")
+                cmd = "/usr/sbin/frontend_idtoken %s" % entry_name
+                tkn_str = subprocessSupport.iexe_cmd(cmd, useShell=True)
+                os.write(fd, tkn_str.encode('utf-8'))
+                os.close(fd)
+                shutil.move(tmpnm, tkn_file)
+                os.chmod(tkn_file, 0o600)
+                logSupport.log.debug("created token %s" % tkn_file)
+            elif os.path.exists(tkn_file):
+                with open(tkn_file, 'r') as fbuf:
+                    for line in fbuf:
+                        tkn_str += line
+        except Exception as err:
+            logSupport.log.warning('failed to create %s' % tkn_file)
+            for i in sys.exc_info():
+                logSupport.log.warning('%s' % i)
+        finally:
+            if os.path.exists(tmpnm):
+                os.remove(tmpnm)
         return tkn_str
 
     def populate_pubkey(self):
__END_PATCH__
popd
