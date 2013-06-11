# Ossec server provisioning recipe
# install the ossec-hids-server package and push the
# default configuration from the templates

include_recipe "postfix::default"

class Chef::Recipe
  include OssecCore
end


package "ossec-hids-server"

service "ossec-server" do
  provider Chef::Provider::Service::Init
  service_name node[:ossec][:server][:server_name]
  supports :start => true, :stop => true, :restart => true, :status => true
  action [ :start ]
  only_if "test -e /var/ossec/etc/ossec.conf"
end

# Get all the agents at once, more efficient
ossec_agents = search(:node,
                      "roles:ossec-agent "\
                      "AND chef_environment:#{node.chef_environment}")

# resolve searches in server rules
ossec_hostname_search()

# resolve email_alerts location searches
ossec_event_location_search()

# initialize the agent hash on the first run
if node[:ossec][:agents].nil?
  node.set[:ossec][:agents] = {}
end

ossec_agents.each do |agent|
  # don't process thy self
  if agent.ipaddress == node.ipaddress
    next
  end

  agent_hash = ossec_agent_create_parameters(agent, node)

  # this agent is running fine, go to the next one
  if ossec_agent_is_active?(agent_hash[:id])
    node.set[:ossec][:agents][agent_hash[:id]][:status] = "active"
    next
  end

  # check that the agent ID still point to the same IP and hostname
  # otherwise, delete the record from the ossec server
  if not ossec_verify_agent(agent_hash, node)
    Chef::Log.info("OSSEC: deleting server record for agent '#{agent_hash[:id]}'")
    node[:ossec][:agents].delete(agent_hash[:id])
  end

  # if this agent doesn't have a valid key, generate one
  if not ossec_agent_has_valid_key?(agent_hash, node)
    Chef::Log.info("OSSEC: agent '#{agent_hash[:id]}' needs a key. Generating one.")
    agent_hash[:key] = ossec_generate_agent_key(agent_hash)
    agent_hash[:rid] = "todo"
    agent_hash[:status] = "key_exists"
  end

  # save agent parameters
  agent_hash.each do |k,v|
    node.set[:ossec][:agents][agent_hash[:id]][k] = v
  end

  # Don't continue if the agent has a valid key but doesn't know it yet
  if not ossec_agent_knows_key?(agent_hash, agent)
    Chef::Log.info("OSSEC: agent '#{agent_hash[:id]}' didn't pick up its key yet.")
    next
  end

  # Check if it needs a queue cleanup
  if ossec_agent_needs_rid?(agent_hash[:id], agent)
    ruby_block "ossec queue rid" do
      block do
        if File.exists?("/var/ossec/queue/rids/#{agent_hash[:id]}")
          File.delete("/var/ossec/queue/rids/#{agent_hash[:id]}")
          Chef::Log.info("OSSEC: deleted queue for agent '#{agent_hash[:id]}'")
        else
          Chef::Log.info("OSSEC: No queue for agent '#{agent_hash[:id]}.'")
        end
        node.set[:ossec][:agents][agent_hash[:id]][:rid] = "done"
      end
      notifies :restart, "service[ossec-server]"
    end
    # done with this agent, go to the next one
    next
  end

  # If after all that, the agent is still not active, mark it as so
  if not ossec_agent_is_active?(agent_hash[:id])
    if ossec_agent_is_zombie?(agent_hash[:id])
      node.set[:ossec][:agents][agent_hash[:id]][:status] = "zombie"
      # if the agent is a zombie, perform a rid of its queue on the next run
      Chef::Log.info("OSSEC: agent #{agent_hash[:id]} is a zombie. " +
                     "Request queue deletion")
      node.set[:ossec][:agents][agent_hash[:id]][:rid] = "todo"
    else
      node.set[:ossec][:agents][agent_hash[:id]][:status] = "disconnected"
      Chef::Log.info("OSSEC: agent #{agent_hash[:id]} connection failed. " +
                     "Performing restart")
      cmd = Chef::ShellOut.new("/var/ossec/bin/agent_control -R #{agent_hash[:id]}")
      cmd_ret = cmd.run_command
    end
  end
end

# Remove the attributes of an agent from the ossec server if the agent doesn't
# exist on Chef and the last keep_alive is more than 7 days old
node[:ossec][:agents].each do |agent_id, params|
  if params[:status].eql?('key_exists')
    next
  end

  agent = ossec_agents.select{ |n| (n[:ossec][:agents].has_key?(agent_id) \
                                    && n[:ossec][:agent][:enable])
                              }.first

  if not agent.nil?
    next
  end
  if ossec_agent_should_be_removed?(agent_id)
    Chef::Log.info("OSSEC: Removing old agent '#{agent_id}' - '#{params[:name]}'")
    node[:ossec][:agents].delete(agent_id)
  else
    Chef::Log.info("OSSEC: agent '#{agent_id}' - '#{params[:name]}' is candidate for removal")
    node.set[:ossec][:agents][agent_id][:status] = 'candidate_for_removal'
  end
end

template "/var/ossec/etc/client.keys" do
  mode 0440
  owner "root"
  group "ossec"
end

template "/var/ossec/rules/local_rules.xml" do
  owner "root"
  group "root"
  notifies :restart, "service[ossec-server]"
end

template "/var/ossec/etc/local_decoder.xml" do
  owner "root"
  group "root"
  notifies :restart, "service[ossec-server]"
end

template "/var/ossec/etc/ossec.conf" do
  source "ossec-server.conf.erb"
  owner "ossec"
  group "ossec"
  variables( :ossec_agents => ossec_agents )
  notifies :restart, "service[ossec-server]"
end

template "/var/ossec/etc/internal_options.conf" do
  mode 0444
  owner "root"
  group "root"
  notifies :restart, "service[ossec-server]"
end
