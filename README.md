# Galle

A simple proxy that filters incoming connections based on request source.

The proxy is written in python.

It supports generic tcp filtering using "PROXY protocol" to get information on the real source of the connection.

The general idea is that this proxy will listen to a user defined list of ports and will forward only whitelisted ips/hostnames to upstream. Each port is "mapped" to a specific upstream.

Rejected connections can be simply dropped or redirected to a different upstream.

Optionally, galle can listen to a given port (see the given sample config.ini) for ban requests on specific ips. The ip blacklist is applied globally before the whitelists. Connections from banned ips are always dropped.

The ban requests must be provided like this:
curl <galle address>:<ban_requests_port> -s -o /dev/null -d "192.168.1.12 10 EOF"
This will ban ip "192.168.1.12" for 10 seconds. The closing "EOF" string is mandatory because we want to be sure for how long the ban should last.

## Usage

    python galle.py <path to ini config file>

A sample config file and Dockerfile is provided.
