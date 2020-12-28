@load policy/tuning/json-logs.zeek
# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Enable capture loss tcp statistics
@load policy/misc/capture-loss

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

########################### Scan plugins ##############################
#######################################################################
@load misc/scan
# Failed connection attempts are tracked over this time interval
# for the address scan detection.
redef Scan::addr_scan_interval = 2min;
# The threshold of the unique number of hosts a scanning host
# has to have failed connections with on a single port.
redef Scan::addr_scan_threshold = 128;
# Failed connection attempts are tracked over this time interval
# for the port scan detection.
redef Scan::port_scan_interval = 2min;
# The threshold of the number of unique ports a scanning host
# has to have failed connections with on a single victim host.
redef Scan::port_scan_threshold = 256;

# Detect traceroute being run on the network.
@load misc/detect-traceroute

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect
@load protocols/ftp/detect-bruteforcing

# Geographic detections and logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

################### Information Gathering plugins #####################
#######################################################################
# Log some information about web applications being used by users
# on your network.
#@load misc/app-stats

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps
# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
@load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
@load policy/protocols/conn/mac-logging

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# Load Ja3
@load ja3

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
# @load protocols/ssl/notary

#################### Extracted file informations ######################
#######################################################################

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
#@load frameworks/files/detect-MHR

# File extraction
@load file-extraction

# http POST configurations
@load log-add-http-post-bodies
# max POST body loggable bites
redef Corelight::http_post_body_length = 300;

#Add country in zeek_conn (You need a docker image with maxmind database)
@load certego