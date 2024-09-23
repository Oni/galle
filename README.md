# Galle

A simple tcp proxy that filters incoming connections based on request source.

The proxy is written in python.

It supports generic tcp filtering using "PROXY protocol" to get information on the real source of the connection.

The general idea is that this proxy will listen to a user defined list of ports and will forward only whitelisted ips/hostnames to upstream. Each port is "mapped" to a specific upstream.

Rejected connections can be simply dropped or redirected to a different upstream.

## Usage

    python galle.py <path to ini config file>

A sample config file and Dockerfile is provided.
