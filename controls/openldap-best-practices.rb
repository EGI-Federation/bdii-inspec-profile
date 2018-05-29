# encoding: utf-8
# copyright: 2018, The Authors
#

title 'Best Practices'

# you add controls here
control 'file permissions' do
  impact 0.75
  title 'File and directory permissions'
  desc 'Check file and directory ownership and permissions'

  client_config_file = '/etc/openldap/ldap.conf'
  describe file(client_config_file) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end

  server_config_dir = '/etc/openldap/slapd.d/'
  describe directory(server_config_dir) do
    # its('owner') { should eq 'ldap' }
    its('group') { should eq 'ldap' }
    its('mode') { should cmp '0750' }
  end
end

control 'Schema file permissions' do
  impact 0.75
  title 'ldap schema files'
  desc 'The ldap schema files must not be writeable except by root'

  describe directory('/etc/openldap/schema') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end

  ldif_files = command('find /etc/openldap/schema -type f').stdout.split(/\n/)
  ldif_files.each do |f|
    describe file(f) do
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
      its('mode') { should cmp '0444' }
    end
  end
end

control 'Permissions for Rootdn Password' do
  impact 0.75
  title 'Root DN password'
  desc 'Protect the powerful Root Distinguished Name password from \n
            disclosure except to the ldap server group and root.'
  files_with_rootpw = command('grep -ir -l rootpw /etc/').stdout.split(/\n/)
  files_with_rootpw.each do |f|
    describe file(f) do
      its('owner') { should eq 'root' }
      its('group') { should eq 'ldap' }
      its('mode') { should cmp '0640' }
    end
  end
end

control 'Protect Database' do
  impact 0.75
  title 'Protect the LDAP database from Inappropriate direct access'
  desc "The directory and files storing the LDAP database should \n
              be owned by the ldap user and the ldap group, and have \n
              permission 0600."
  describe directory('/var/lib/ldap') do
    its('owner') { should eq 'ldap' }
    its('group') { should eq 'ldap' }
  end

  ldap_dbs = command('find /var/lib/ldap -name "*db*"').stdout.split(/\n/)
  ldap_dbs.each do |db_file|
    describe file(db_file) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'ldap' }
      its('group') { should cmp 'ldap' }
    end
  end
end

control 'Protect LDAP Export/Import Files' do
  impact 0.75
  title 'Protect LDIF files'
  desc "Rather than attack the LDAP database directly it's often easier to \n
              obtain the information through backup files or import/export files \n
              typically stored in LDIF format. Look for such files on the local \n
              system and review any import or export processes that are being\n
              used. \n
              Discussion: Any backup, export, import or other files containing the \n
              LDAP database must be removed when no longer needed, and \n
              protected with minimal read access, such as owned by root with \n
              permissions 600."
  ldif_files = command('find / -name "*.ldif"').stdout.split(/\n/)

  ldif_files.each do |f|
    describe file(f) do
      its('mode') { should cmp '0600' }
      its('owner') { should eq 'root' }
    end
  end
end

control '1.12 Dedicated System' do
  impact 0.75
  title 'Put LDAP on a dedicated system if you can'
  desc 'In order to reduce the risk of potential vulnerabilities in other\n
             services jeopardizing the LDAP server, consider installing \n
             OpenLDAP on a dedicated system, or a server with minimal\n
             services.\n
             Discussion: System should be dedicated to running OpenLDAP.\n
             If possible, only administrative services like SSH and other closely\n
             related authentication services such as radius should be running\n
             on the same system.'
  only_if do
    false
  end
end

control '1.13 Restricted File System Access' do
  impact 0.75
  title 'Run openldap in a contained environment'
  desc 'In case the slapd service is exploited remotely file systems access\n
             restrictions will prevent the exploit from getting access to system\n
             files and executables.\n
             Discussion: Consider running slapd in a chroot environment, or using\n
             SELinux, or Solaris RBAC, to restrict access to system files for the\n
             slapd user (typically ldap).'
  only_if do
    false
  end
end

control '2.1 LDAPv2 Bind' do
  impact 0.75
  title 'LDAPv2 Bind should be disabled'
  desc 'Note the bind_v2 option is not enabled by default.\n
             It allows the old version 2 bind, and does not enable support\n
             for the entire LDAPv2 protocol.\n
             Discussion: Do not allow the older ldapv2 bind request unless\n
             compatibility with old LDAP clients is absolutely necessary.\n
             Do NOT specify allow bind_v2 in the slapd.conf file.'
  ldap_config_files = command('find / -name "slapd.conf" ').stdout.split(/\n/)
  ldap_config_files.each do |f|
    describe file(f) do
      its('content') { should_not match(/allow bind_v2/) }
    end
  end
end

control 'RootDN password storage' do
  impact 0.75
  title 'Root DN password should not be kept in plain text'
  desc 'Since the Root Distinguished Name password provides full unrestricted\n
             administrative access to the ldap data, it needs to be carefully protected\n
             with a secure salted hash value.\n
             The slappasswd(8) command may be used to generate the hash.\n
             Administrators will need to update and may need to share the contents\n
             of the slapd.conf file, placing the rootdn password in a separate file\n
             helps protects it from accidental disclosure.\n
             Discussion: The Root Distinguished Name password must NOT be stored\n
             directly in the slapd.conf file. It may stored in an alternative database\n
             or service such as SALS or included from a separate protected file\n
             using a salted MD5 hash value.\n
             Such as: rootdn  "cn=Manager,dc=example,,dc=com" rootpw {SMD5}sK9tP8eUpB. . .Cq4gFk='
  only_if do
    false
  end
end
