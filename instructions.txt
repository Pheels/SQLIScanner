
Below is a step by step guide to run sqlifirewall on your apache web server.

1. Install the relevant packages:
$sudo apt-get install libpcre3 libpcre3-dev 

2. Get the package via http: 
wget "https://www.dropbox.com/s/rvgg0jrwihtclfa/sqlifirewall.tgz?dl=0”

3. Extract the files:
tar -xvzf sqlifirewall.tgz?dl=0

PLEASE NOTE: Please change Apache’s access log format to ‘common’, within the config file.
#define logfile “/var/www/example/access.log”      

4. change directory to sqlifirewall and make the executable file
$ cd /sqlifirewall; make

5. Execute
$ ./sqlifirewall

6. When an attack is attempted on the server, the log line is stored in a generated file named SQLILOG.txt

<——How to unblock an IP address from the server—->

1. Open iptables.rules file 
$ iptables-save > /etc/iptables.rules && nano /etc/iptables.rules

2. Delete line containing relevant IP Address

3. Save the results
$ iptables-restore < /etc/iptables.rules && iptables-save


