# encoding: utf-8
# copyright: 2018, The Authors

title 'CVE tests'

# you add controls here
control 'CVE-2017-17740' do
  impact 0.75
  title 'CVE-2017-17740'
  desc 'if we enable overlay nops & memberof together, we can segfault'
  # We need to get the package version number in a format Gem::Version understands
  # The versions usually contain a '.el-7' or similar, so we need to split on letters.
  only_if do
    package('openldap-servers').version { cmp <= '2.4.5' }
  end
  ldif_files = command("find /etc/openldap/ -name '*.ldif'").stdout.split(/\n/)
  ldif_files.each do |f|
    describe file(f) do
      its('content') { should_not match(/nops/i) }
      its('content') { should_not match(/moddn/i) }
    end
  end
end

control 'CVE-2015-6908' do
  impact 0.5
  title 'CVE-2015-6908'
  desc 'The ber_get_next function in libraries/liblber/io.c in OpenLDAP 2.4.42\n
             and earlier allows remote attackers to cause a denial of service \n
             (reachable assertion and application crash) via crafted BER data,\n
             as demonstrated by an attack against slapd. '
  ref ' CVE-2015-6908', url: 'https://www.cvedetails.com/cve/CVE-2015-6908/'

  describe package('openldap') do
    its('version') { should cmp > '2.4.42 ' }
  end
end

control 'CVE-2002-0045' do
  impact 0.75
  title 'CVE-2002-0045'
  desc 'slapd in OpenLDAP 2.0 through 2.0.19 allows local users, and\n
             anonymous users before 2.0.8, to conduct a "replace" action on\n
             access controls without any values, which causes OpenLDAP to\n
             delete non-mandatory attributes that would otherwise be protected\n
             by ACLs.'
  tag 'openldap'
  ref 'CVE-2002-0045', url: 'https://www.cvedetails.com/cve/CVE-2002-0045/'
  ref 'OpenLDAP mailing list', url: 'https://www.openldap.org/lists/openldap-announce/200201/msg00002.html'

  only_if do
    package('openldap').version < '2.0.19'
  end
end

control 'CVE-2004-0112' do
  impact 0.75
  title 'CVE-2004-0112'
  desc 'The SSL/TLS handshaking code in OpenSSL 0.9.7a, 0.9.7b, and 0.9.7c,\n
             when using Kerberos ciphersuites, does not properly check the length\n
             of Kerberos tickets during a handshake, which allows remote attackers\n
             to cause a denial of service (crash) via a crafted SSL/TLS handshake that\n
             causes an out-of-bounds read.'
  tag 'openldap'
  ref 'CVE-2004-0112', url: 'https://www.cvedetails.com/cve/CVE-2004-0112/'

  only_if do
    package('openssl').installed?
  end
  describe package('openssl') do
    its('version') { should cmp > '0.9.7' }
  end
end
