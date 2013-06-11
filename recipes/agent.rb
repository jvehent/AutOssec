# Ossec Agent provisioning recipe
# install the ossec-hids-client package, push the global
# and role specific configuration for the node
# get a key from the ossec-server if there's one

if not node['lsb']['codename'].eql?('lucid')
  return true
end

class Chef::Recipe
  include OssecCore
end


# Run this recipe if the node is an agent. Since the ossec::agent recipe is
# added to the base role, ossec-servers will run it as well, making this check
# necessary
if not node[:ossec][:agent][:enable]
  # return will exit this recipe
  # and continue the chef provisioning
  Chef::Log.info("OSSEC: agent is not enabled on this node")
  return true
end

# Search for the ossec server, and do nothing if there's none
ossec_server = search(:node,
                      "role:ossec-server " \
                      "AND chef_environment:#{node.chef_environment}"
                     ).first
if ossec_server.nil?
  Chef::Log.info("OSSEC: No ossec server available. Agent will not be provisionned")
  return true
end

# install the agent package
package "ossec-hids-client"

# define the agent parameters
agent_hash = ossec_agent_create_parameters(node, ossec_server)

# check for the agent configuration on the server. if the server has none, do
# not continue the provisioning. If the server has a configuration for this
# agent, store the parameters on the node and continue
if ossec_verify_agent(agent_hash, ossec_server)
  node.set[:ossec][:agents][agent_hash[:id]] = ossec_server[:ossec][:agents][agent_hash[:id]].to_hash
else
  Chef::Log.info("OSSEC: this agent is unknown on the ossec server")
  return true
end

# Make sure that the server prepared a key for us
unless ossec_agent_has_valid_key?(agent_hash, ossec_server)
  Chef::Log.info("OSSEC: Server doesn't have a valid key for agent.")
  return true
end

service "ossec-agent" do
  provider Chef::Provider::Service::Init
  service_name node[:ossec][:client][:server_name]
  supports :start => true, :stop => true, :restart => true, :status => true
  action [ :start ]
  only_if "test -e /var/ossec/etc/ossec.conf && test -e /var/ossec/etc/client.keys"
end

# Get the IP of the ossec server
ossec_server_ip = ossec_server[:network][:lanip] || ossec_server.ipaddress
# Expand the local syslog files searches from the node attributes
ossec_set_local_syslog_file_ignore_flags!()
ossec_set_local_file_ignore_flags!()
template "/var/ossec/etc/ossec.conf" do
  source "ossec-agent.conf.erb"
  owner "ossec"
  group "ossec"
  variables(:ossec_server_ip  => ossec_server_ip )
  notifies :restart, "service[ossec-agent]"
end

# If client.keys is modified, ask for a queue rid on the server
template "/var/ossec/etc/client.keys" do
  mode 0440
  owner "root"
  group "ossec"
  notifies :create, "ruby_block[set-rid-flag]"
  notifies :restart, "service[ossec-agent]"
end

# "set-rid-flag" is not run by default, but called when the agent's key
# is modified (or created)
ruby_block "set-rid-flag" do
  block do
    # if the server side rid flag is not set to "done",
    # request a queue rid by setting the agent side flag to "todo"
    if ossec_server[:ossec][:agents][agent_hash[:id]][:rid].eql?("none")
      node.set[:ossec][:agents][agent_hash[:id]][:rid] = "todo"
      Chef::Log.info "Setting Queue Rid Flag on"
    end
  end
  action :nothing
end

# unset rid flag if necessary, check that at every run
if node[:ossec][:agents][agent_hash[:id]][:rid].eql?("todo") \
   and ossec_server[:ossec][:agents][agent_hash[:id]][:rid].eql?("done")
  ruby_block "unset rid flag" do
    block do
      node.set[:ossec][:agents][agent_hash[:id]][:rid] = "none"
      Chef::Log.info "Setting Queue Rid Flag off"
    end
    notifies :restart, "service[ossec-agent]"
  end
end
