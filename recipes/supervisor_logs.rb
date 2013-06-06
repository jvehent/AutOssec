# This recipe will list the log file created by supervisor
# and add the necessary attributes to have those monitored
# by the local ossec-agent

# cleanup, before recreation
node[:ossec][:local_syslog_files].each do |logfile, params|
  if logfile =~ /supervisor/
    node[:ossec][:local_syslog_files].delete(logfile)
  end
end

# each program run by supervisor has a set of logfiles
node[:supervisor][:programs].each do |program_name, config|
  total_procs = config[:numprocs] || 1
  # each process of a program has its own log file
  0.upto(total_procs.to_i - 1) do |numproc|
    logfile = "#{node[:supervisor][:log_path]}/#{program_name}_#{numproc}_stdout.log"
    # add the stdout supervisor log file
    node[:ossec][:local_syslog_files][logfile] = {
     'apply_to' => "fqdn:#{node.fqdn}",
     'log_format' => 'syslog',
     'use_here' => 'true'
    }
    log("Ossec::Supervisor: Adding '#{logfile}' to monitored log files")

    logfile = "#{node[:supervisor][:log_path]}/#{program_name}_#{numproc}_stderr.log"
    # add the stderr supervisor log file
    node[:ossec][:local_syslog_files][logfile] = {
     'apply_to' => "fqdn:#{node.fqdn}",
     'log_format' => 'syslog',
     'use_here' => 'true'
    }
    log("Ossec::Supervisor: Adding '#{logfile}' to monitored log files")

  end
end
