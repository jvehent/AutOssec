# Core function for OSSEC
# Used by the server and agent recipes

module OssecCore

  def ossec_hostname_search()
    # resolve the hostname_search of a rule to a list of hosts
    node[:ossec][:rules].each do |id,params|
      if not params.nil?
        params[:body].each do |key, value|
          if key.eql?('hostname_search')
            hosts_list = search(:node,
                                "(#{value}) AND roles:ossec-agent "\
                                " AND chef_environment:#{node.chef_environment}"
                                ).map {|n| n.hostname}
            if hosts_list.empty?
              # search didn't return anything
              # store a dummy value in the attributes
              Chef::Log.info("OSSEC: Hostname search returned empty result. " +
                             "'#{value}'")
              params[:body][:hostname] = "invalid-search-returned-empty-result"
            else
              # store in the node params but discard the last char
              params[:body][:hostname] = hosts_list.join('|')
            end
          end
        end
      end
    end
  end


  def ossec_event_location_search()
    # resolve the location search of an email_alert block to a hostname
    node[:ossec][:email_alerts].each do|recipient,params|
      if params.has_key?('event_location_search')
        dest = search(:node,
                      "(#{params[:event_location_search]}) " \
                      "AND chef_environment:#{node.chef_environment}"
                     ).map {|n| n.hostname}
        node.default[:ossec][:email_alerts][recipient][:resolved_search] = dest
      end
    end
  end


  def ossec_set_local_syslog_file_ignore_flags!()
    # go through the list of local logfile and check the ones that
    # apply to this node
    unless node[:ossec][:local_syslog_files].nil?
      node[:ossec][:local_syslog_files].each do |logfile,params|
        locations = search(:node,
                           "(#{params[:apply_to]}) " \
                           "AND chef_environment:#{node.chef_environment}"
                          ).map {|n| n.ipaddress}
        if locations.include?(node.ipaddress)
          node.default[:ossec][:local_syslog_files][logfile][:use_here] = "true"
        else
          node.default[:ossec][:local_syslog_files][logfile][:use_here] = "false"
        end
      end
    end
  end


  def ossec_set_local_file_ignore_flags!()
    # go through the list of locally ignored and check the ones that
    # apply to this node
    if not node[:ossec][:syscheck][:local_ignore].nil?
      node[:ossec][:syscheck][:local_ignore].each do |file,params|
        locations = search(:node,
                           "(#{params[:apply_to]}) " \
                           "AND chef_environment:#{node.chef_environment}"
                          ).map {|n| n.ipaddress}
        if locations.include?(node.ipaddress)
          node.default[:ossec][:syscheck][:local_ignore][file][:use_here] = "true"
        else
          node.default[:ossec][:syscheck][:local_ignore][file][:use_here] = "false"
        end
      end
    end
  end


  def ossec_agent_create_parameters(agent, server)
    # Returns a hash with the identiers for this agent
    agent_hash = {}
    # IP is defined by lanip, if available (ohai plugin network_addr)
    # or by the default ipaddress otherwise
    agent_hash[:ip] = agent[:network][:lanip] || agent.ipaddress

    # Ossec limits the agents name length to 32 characters, so to avoid
    # names collisions, we concatenate the agent_ip with the first characters
    # of the hostname
    name = agent_hash[:ip] + "_" + agent[:hostname]
    agent_hash[:name] = name[0,31]

    # ossec agent id is an integer used to identify an agent. we force that ID
    # to be the IP address without the dots (10.1.2.3 becomes 10123)
    agent_hash[:id] = agent_hash[:ip].gsub(".", "")

    agent_hash[:key] = "undef"
    if server[:ossec][:agents].key?(agent_hash[:id])
      if server[:ossec][:agents][agent_hash[:id]].key?('key')
         agent_hash[:key] = server[:ossec][:agents][agent_hash[:id]][:key]
      end
    end
    agent_hash[:rid] = "none"

    return agent_hash
  end


  def ossec_generate_agent_key(agent_hash)
    # Returns a 64 characters double md5 hash, used as a symetric key
    seed1 = rand(100000000000).to_s
    seed2 = rand(100000000000).to_s
    str1 = Digest::MD5.hexdigest(seed1 + \
                                 agent_hash[:id] + \
                                 agent_hash[:ip] + \
                                 seed2)
    str2 = Digest::MD5.hexdigest(seed2 + \
                                 agent_hash[:name] + \
                                 seed1 + \
                                 agent_hash[:ip] + \
                                 agent_hash[:id])
    key = str1 + str2
    return key
  end


  def ossec_agent_has_valid_key?(agent_hash, server)
    # Does the server have a valid key for this agent ?
    if server[:ossec][:agents].key?(agent_hash[:id])
      if server[:ossec][:agents][agent_hash[:id]].key?('key')
        if server[:ossec][:agents][agent_hash[:id]][:key].length == 64
          return true
        end
      end
    end
    return false
  end


  def ossec_agent_knows_key?(agent_hash, agent)
    # Does the agent have a key that matches the server ?
    if agent.key?('ossec')
      if agent[:ossec].key?('agents')
        if agent[:ossec][:agents].key?(agent_hash[:id])
          if agent[:ossec][:agents][agent_hash[:id]].key?('key')
            if agent[:ossec][:agents][agent_hash[:id]][:key] == agent_hash[:key]
              return true
            end
          end
        end
      end
    end
    return false
  end


  def ossec_verify_agent(agent_hash, server)
    # check if this agent (id, name, ip) is defined on the server
    if server[:ossec][:agents].key?(agent_hash[:id])
      agent_srv_data = server[:ossec][:agents][agent_hash[:id]]
      if agent_srv_data[:name].eql?(agent_hash[:name])
        if agent_srv_data[:ip].eql?(agent_hash[:ip])
          return true
        else
          Chef::Log.info("OSSEC: agent ip mismatch. " +
                         "server has '#{agent_srv_data[:ip]}' " +
                         "agent has '#{agent_hash[:ip]}'")
        end
      else
        Chef::Log.info("OSSEC: agent name mismatch. " +
                       "server has '#{agent_srv_data[:name]}' " +
                       "agent has '#{agent_hash[:name]}'")
      end
    else
      Chef::Log.info("OSSEC: agent name '#{agent_hash[:name]}' " +
                     " ip '#{agent_hash[:ip]}'" +
                     " configuration not found on server.")
    end
    return false
  end


  def ossec_agent_is_active?(id)
    if File.exists?("/var/ossec/bin/agent_control")
      cmd = Chef::ShellOut.new("/var/ossec/bin/agent_control -s -i #{id}")
      cmd_ret = cmd.run_command
      status = cmd.stdout.split(",")
      if status[3] && status[3].eql?("Active")
        return true
      end
    end
    return false
  end


  def ossec_agent_is_zombie?(id)
    if File.exists?("/var/ossec/bin/agent_control")
      cmd = Chef::ShellOut.new("/var/ossec/bin/agent_control -s -i #{id}")
      cmd_ret = cmd.run_command
      status = cmd.stdout.split(",")
      if not status[6] || status[3] =~ /(Never connected|)/
        return true
      elsif status[6] !~ /Unknown/
        last_keep_alive = Time.parse(status[6])
        three_days_ago = (Time.now - (24*60*60*3))
        if three_days_ago > last_keep_alive
          return true
        end
      end
    end
    return false
  end


  def ossec_agent_should_be_removed?(id)
    if File.exists?("/var/ossec/bin/agent_control")
      cmd = Chef::ShellOut.new("/var/ossec/bin/agent_control -s -i #{id}")
      cmd_ret = cmd.run_command
      status = cmd.stdout.split(",")
      if not status[6] or status[6] =~ /Unknown/
        return true
      else
        last_keep_alive = Time.parse(status[6])
        seven_days_ago = (Time.now - (24*60*60*7))
        if seven_days_ago > last_keep_alive
          return true
        end
      end
    end
    return false
  end


  def ossec_agent_needs_rid?(id, agent)
    # Check if the agent queue needs to be removed, either because the server
    # said so, or because the agent asked for it
    if agent[:ossec][:agents][id][:rid].eql?("todo") \
       or node[:ossec][:agents][id][:rid].eql?("todo")
      return true
    else
      return false
    end
  end
end
