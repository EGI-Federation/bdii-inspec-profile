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

control 'Protect the database' do
  impact 0.75
  title 'Protect LDAP DB'
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
