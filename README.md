Description
===========
Fully automated Installation and configuration of ossec-servers and ossec-agents
Manage the key generation and distribution between a server and multiple agents
Clean queues on the server if needed (rid)

Requirements
============
Ubuntu 10.04+
(should work with ossec systems if you have the packages)

Attributes
==========
# General Attributes

The attributes below follow the same namespace syntax that OSSEC does. Refer to
the officiel [OSSEC Documentation](http://www.ossec.net/doc/syntax/ossec_config.html)
for more information.

Default attributes from the cookbook:

    default[:version] = "2.6"
    default[:ossec][:syslog_output][:ip] = "127.0.0.1"
    default[:ossec][:syslog_output][:port] = "514"
    default[:ossec][:syslog_output][:min_level] = "5"
    default[:ossec][:receiver_port] = "1514"
    default[:ossec][:log_alert_level] = "1"
    default[:ossec][:email_alert_level] = "7"
    default[:ossec][:agents] = {}

Default attributes from the ossec-server role:

    :ossec => {
      :email_notification => 'yes',
      :email_to => [
        'ossec@example.net',
      ],
      :email_from => 'ossec-server@example.net',
      :smtp_server => 'localhost',
      :white_list => [
        '127.0.0.1',
        '10.1.0.0/16'
      ],
      :email_alerts => {
        'recipient@example.net' => {
          'level' => '9',
          'group' => 'syscheck',
          'event_location_tag' => 'reputation',
          'event_location_search' => 'roles:*mongodb*',
          'format' => 'sms',
          'rule_id' => '100001',
          'tags' => [
            'do_not_delay',
            'do_not_group'
          ]
        }
      },
      :syscheck => {
        :frequency => '7200',
        :alert_new_files => 'yes',
        :auto_ignore => 'no',
        :directories => {
          '/bin' => {
            'report_changes' => 'no',
            'realtime' => 'yes'
          },
          '/sbin' => {
            'report_changes' => 'no',
            'realtime' => 'yes'
          },
          '/usr/bin' => {
            'report_changes' => 'no',
            'realtime' => 'yes'
          },
          '/usr/sbin' => {
            'report_changes' => 'no',
            'realtime' => 'yes'
          },
          '/etc' => {
            'report_changes' => 'yes',
            'realtime' => 'yes'
          },
          '/tmp' => {
            'report_changes' => 'yes',
            'realtime' => 'no'
          }
        },
        :ignore => [
          '/etc/openvpn/openvpn-status.log',
          '/etc/motd',
          '/etc/mcollective/facts.yaml',
          '/etc/blkid.tab',
          '/etc/mtab',
          '/etc/mail/statistics',
          '/etc/random-seed',
          '/etc/adjtime',
          '/etc/prelink.cache',
          '/etc/dnscache/stats',
          '/etc/dnscache/log',
          '/etc/dnscache2/stats',
          '/etc/dnscache2/log',
          '/etc/tinydns/stats',
          '/etc/tinydns/log'
        ]
      },
      :syslog_files => [
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/daemon.log',
        '/var/log/kern.log',
        '/var/log/mail.log',
        '/var/log/user.log',
        '/var/log/cron.log'
      ],

```email_alerts``` is a hash of recipients and servers. Each recipient will
receive all of the alert for the listed location (the list is a regex).
```event_location_tag``` must contain a valid chef tag. All the nodes listed by
that tag will generate a separate ```email_alerts``` rule.
This is additional to the default list ```email_to``` and is used to send alert to
specific recipients for a limited number of hosts only.

# Local Rules Definitions
Rules are defined in Ruby Hash format and replicate the XML format of regular
[OSSEC Rules Syntax](http://www.ossec.net/doc/syntax/head_rules.html)
Each rule has a head, a body, tags and info (the last 2 being optional)

    head=   <rule id="12345" level="12" frequency="45" timeframe="60">
    body=     <description>Test Rule</description>
    body=     <match>Big Error</match>
    body=     <hostname>server1</hostname>
    tags=     <same_source_ip />
    tags=     <same_source_port />
    info=     <info type="link">http://IjustGotHacked.com</info>
            </rule>

The section below are parsed by the template. The following items are mandatory:
 * head/level
 * body/description

```
    :ossec =>
      :rules => {
        "100001" => {
          :head => {
            :level => "7",
            :maxsize => "65536",
            :frequency => "100",
            :timeframe => "3600",
            :ignore => "5",
            :overwrite => "68321"
          },
          :body => {
            :hostname_search => "recipes:mms-agent",
            :description => "Super Security Rule for application XYZ",
            :match => "super dangerous error happened",
            :regex => "^\d+Hello World$",
            :decoded_as => "vsftpd",
            :category => "windows",
            :srcip => "192.168.1.254",
            :dstip => "10.1.6.23",
            :user => "bob",
            :program_name => "nginx",
            :time => "09:00-18:00",
            :weekday => "monday,tuesday",
            :id => "404",
            :url => "/changepassword.php",
            :if_sid => "100238",
            :if_group => "authentication_success",
            :if_level => "13",
            :if_matched_sid => "12037",
            :if_matched_group => "adduser",
            :if_matched_level => "7",
            :options => "no_email_alert",
            :check_diff => "true",
            :group => "syscheck"
          },
          :tags => [
            "same_source_ip",
            "same_source_port",
            "same_dst_port",
            "same_location"
          ],
          :infos => {
            :link => "http://trac.example.net/ticket/12345",
            :text => "the link above contains additional information"
          }
        }
      }
```

## hostname_search

To the exception of __hostname_search__, all attributes use the same syntax as the
ossec rule in XML format does.
__hostname_search__ in this cookbook represents a search query that is executed by
the server recipe to populate the ```<hostname>``` with the proper list of hosts,
dynamically pulled from chef. Search criterias can be anything that a chef search 
can take. Example: ```recipe:mongodb\:\:replicaset and tags:reputation```

# Local Decoders Definitions
Decoders are defined in JSON format and replicate the XML format of regular
[OSSEC Decoder Syntax](http://www.ossec.net/doc/syntax/head_decoders.html)

    :ossec => {
      :decoders => {
        'apache-errorlog' => {
          :program_name => '^httpd|^apache2',
          :prematch => {
            :parser => '^\S+ [\w+\s*\d+ \S+ \d+] [\S+] |^[warn] |^[notice] |^[error]'
          },

        },
        'apache-errorlog-ip-custom' => {
          :parent => 'apache-errorlog',
          :prematch => {
            :offset => 'after_parent',
            :parser => '^[client'
          },
          :regex => {
            :offset => 'after_prematch',
            :parser => '^ (\d+.\d+.\d+.\d+)]'
          },
          :order => 'srcip'
        },
        'web-accesslog-custom' => {
          :parent => 'web-accesslog',
          :type => 'web-log',
          :prematch => {
            :parser => '^\d+.\d+.\d+.\d+ |^::ffff:\d+.\d+.\d+.\d+'
          },
          :regex => {
            :parser => '^\d+.\d+.\d+.\d+ \S+ (\d+.\d+.\d+.\d+) \S+ \S+ \S+ [\S+ \S\d+] "\w+ (\S+) HTTP\S+ (\d+) \S+ "(\S+)"'
          },
          :order => 'srcip, url, id, extra_data'
        }
      }
    }

```prematch``` and ```regex``` are hashes that can have an ```offset``` value and
always have a ```parser``` value. See the ossec documentation for more information.

Usage
=====
* `recipe[ossec-server]` should be a stand alone installation
* `recipe[ossec-agent]` should be added (via role[ossec-agent]) to all the nodes of the
environment

Author
======
Julien Vehent - julien@linuxwall.info - http://jve.linuxwall.info
