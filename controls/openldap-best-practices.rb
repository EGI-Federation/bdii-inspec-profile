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
  server_config_dir = '/etc/openldap/slapd.d/'

  describe file(client_config_file) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end

  describe directory(server_config_dir) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
