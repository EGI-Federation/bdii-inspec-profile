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
