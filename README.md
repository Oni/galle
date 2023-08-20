# Galle

A simple proxy that filters incoming connections based on request source.

The proxy is written in python.

It supports http filtering (based 'X-Forwarded-For' line in header) and it's supposed to be used after a properly configured nginx instance.

It also support generic tcp filtering using "PROXY protocol" to get information on the real source of the connection.

The general idea is that this proxy will listen to a user defined list of ports and will forward only whitelisted ips/hostnames to upstream. Each port is "mapped" to a specific upstream.

## Usage

    python galle.py <path to ini config file>

A sample config file is provided.

A Dockerfile is also provided.
