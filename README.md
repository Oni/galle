# Galle

A simple tcp/udp proxy that filters incoming connections based on request source.

This proxy is written in pure python.

Tcp filtering supports "PROXY protocol" to get information on the real source of the connection. Udp proxy doesn't support any derivate of "PROXY protocol" for now.

The general idea is that this proxy will listen to a user defined list of ports and will forward only whitelisted ips/hostnames to upstream. Each "whitelist" is mapped to a specific upstream.

Rejected connections are dropped.

Galle also holds a list of blacklisted ips. All connections coming from blacklisted ips are *always* dropped and *never* follow redirect rules.

## Remote control

Optionally, galle can be remotely controlled if a valid 'control_port' is provided by the config file. For now the following commands are supported:

    requests.post(<galle ip>:<control_port>, data={'verb': 'ban_set', 'ips': <ip networks separated with '-'>})

Example:

    requests.post(15.58.84.12:5656, data={'verb': 'ban_set', 'ips': '75.48.152.1/16-56.12.12.1/36'})

This will reset the list of banned ips and will be set to the new 'ips' list. The ban is permanent, unless lifted with another 'ban_set' command.

## Usage

    python galle.py <path to json config file>

A sample config file and Dockerfile is provided.
