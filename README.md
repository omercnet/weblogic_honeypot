# WebLogic honeypot
Cymmetria Research, 2018.

https://www.cymmetria.com/

Written by: Omer Cohen (@omercnet)
Special thanks: Imri Goldberg (@lorgandon), Itamar Sher, Nadav Lev

Contact: research@cymmetria.com

WebLogic Honeypot is a low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware. This is a Remote Code Execution vulnerability. The honeypots does a simple simulation of the WebLogic server and will allow attackers to use the vulnerability to attempt to execute code, and will report of such attempts.

It is released under the MIT license for the use of the community, pull requests are welcome!


# Usage

	Usage: weblogic_server.py [OPTIONS]

	  A low interaction honeypot for the Oracle Weblogic wls-wsat component
	  capable of detecting CVE-2017-10271, a remote code execution vulnerability

	Options:
	  -h, --host TEXT     Host to listen
	  -p, --port INTEGER  Port to listen
	  -v, --verbose       Verbose logging
	  --hpfserver TEXT    hpfeeds Server
	  --hpfport INTEGER   hpfeeds Port
	  --hpfident TEXT     hpfeeds Ident
	  --hpfsecret TEXT    hpfeeds Secret
	  --hpfchannel TEXT   hpfeeds Channel
	  --serverid TEXT     hpfeeds ServerID/ServerName
	  --help              Show this message and exit.

Run without parameters to listen on default port (8000).


See also
--------

https://cymmetria.com/blog/honeypots-for-oracle-vulnerabilities/

http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10271

Please consider trying out the MazeRunner Community Edition, the free version of our cyber deception platform.
https://community.cymmetria.com/
