# encoding: utf-8
# copyright: 2018, The Authors

title 'CVE tests'

# you add controls here
control 'CVE-2017-17740' do
  impact 0.75
  title ''
  desc 'if we enable overlay nops & memberof together, we can segfault'
  # We need to get the package version number in a format Gem::Version understands
  # The versions usually contain a '.el-7' or similar, so we need to split on letters.
  v = Gem::Version.new(package('openldap-servers').version.split(/\.[a-z]/).first)
  if v <= Gem::Version.new('2.4.45')
    ldif_files = command("find /etc/openldap/ -name '*.ldif'").stdout.split(/\n/)
    ldif_files.each do |f|
      describe file(f) do
        its('content') { should_not match(/nops/i) }
        its('content') { should_not match(/moddn/i) }
      end
    end
  else
    puts "Openldap servers package version is #{package('openldap-servers').version}"
  end
end
