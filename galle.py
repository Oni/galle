from __future__ import annotations

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import asyncio
import logging
import signal
import ipaddress
from typing import List, Deque
from functools import partial
import socket
from collections import deque
import pathlib
import configparser

from proxyprotocol.server import Address


LOG = logging.getLogger(__name__)
BUFFER_LEN = 1024
UPSTREAM_CONNECTION_TIMEOUT = 5  # seconds


async def main() -> int:
    """The main function: gather() all servers listed in config."""
    parser = ArgumentParser(
        description=__doc__, formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "config",
        metavar="<config file>",
        type=pathlib.Path,
        nargs=1,
        help="the location of the *.ini config file",
    )
    args = parser.parse_args()

    config_path = args.config[0]
    if not config_path.is_file():
        print(f"Unable to locate {config_path}")
        return 1

    config = configparser.ConfigParser()
    config.read(config_path)

    try:
        config_log_level = config.get("logging", "level")
    except configparser.NoSectionError:
        print("Invalid config file: no [logging] section")
        return 1
    except configparser.NoOptionError:
        print("Invalid config file: no 'level' option in [logging] section")
        return 1

    try:
        log_level = {
            "error": logging.ERROR,
            "warn": logging.WARN,
            "info": logging.INFO,
            "debug": logging.DEBUG,
        }[config_log_level]
    except KeyError:
        print(
            "Invalid config file: 'level' option in [logging] section must be 'error', 'warn', "
            "'info' or 'debug'"
        )
        return 1

    logging.basicConfig(level=log_level, format="%(asctime)-15s %(name)s %(message)s")

    configs = {"http": []}
    for section in config.sections():
        if section != "logging":
            try:
                mode = config.get(section, "mode")
            except configparser.NoOptionError:
                print(
                    f"Invalid config file: missing 'mode' option in [{section}] section"
                )
                return 1
            if mode not in ("http",):
                print(
                    f"Invalid config file: 'mode' option in [{section}] section must be 'http'"
                )
                return 1

            try:
                listening_port_s = config.get(section, "listening_port")
            except configparser.NoOptionError:
                print(
                    f"Invalid config file: missing 'listening_port' option in [{section}] section"
                )
                return 1
            try:
                listening_port = int(listening_port_s)
            except ValueError:
                print(
                    f"Invalid config file: 'listening_port' option in [{section}] section must be "
                    "an int"
                )
                return 1

            try:
                allowed_hosts = [
                    x.strip() for x in config.get(section, "allowed_hosts").split(",")
                ]
            except configparser.NoOptionError:
                print(
                    f"Invalid config file: missing 'allowed_hosts' option in [{section}] section"
                )
                return 1

            try:
                allowed_ips = [
                    x.strip() for x in config.get(section, "allowed_ips").split(",")
                ]
            except configparser.NoOptionError:
                print(
                    f"Invalid config file: missing 'allowed_ips' option in [{section}] section"
                )
                return 1

            configs[mode].append((section, listening_port, allowed_hosts, allowed_ips))

    loop = asyncio.get_event_loop()
    forevers = []
    for upstream, listening_port, allowed_hosts, allowed_ips in configs["http"]:
        allowed_addresses = [Address(x) for x in allowed_hosts]
        allowed_ip_networks = []
        for allowed_ip in allowed_ips:
            try:
                allowed_ip_networks.append(ipaddress.ip_network(allowed_ip))
            except ValueError as err:
                LOG.error(
                    "Unable to translate %s to a valid ip range: skipping", allowed_ip
                )
                LOG.error(err.args[0])

        try:
            server = await make_server(
                listening_port,
                Address(upstream),
                "http",
                allowed_addresses,
                allowed_ip_networks,
            )
        except OSError as err:
            LOG.error("Unable to run http proxy at local port %s", listening_port)
            LOG.error(err.strerror)
        else:
            forever = asyncio.create_task(server.serve_forever())
            LOG.info(
                "Started serving http proxy at local port %s that will forward traffic to %s",
                listening_port,
                upstream,
            )
            try:
                loop.add_signal_handler(signal.SIGINT, forever.cancel)
                loop.add_signal_handler(signal.SIGTERM, forever.cancel)
            except NotImplementedError:
                # windows
                pass

            forevers.append(forever)
    try:
        await asyncio.gather(*forevers)
    except asyncio.CancelledError:
        pass
    return 0


def make_server(
    listening_port: int,
    upstream: Address,
    mode: str,
    allowed_addresses: List[Address],
    allowed_ip_networks: List[ipaddress.IPv4Network],
) -> asyncio.coroutine:
    """Return a server that needs to be awaited."""

    address = Address(f"0.0.0.0:{listening_port}")
    if mode == "http":
        proxy_partial = partial(
            proxy,
            upstream=upstream,
            allowed_addresses=allowed_addresses,
            allowed_ip_networks=allowed_ip_networks,
        )
    return asyncio.start_server(proxy_partial, address.host, address.port)


async def proxy(
    downstream_reader: asyncio.StreamReader,
    downstream_writer: asyncio.StreamWriter,
    upstream: Address,
    allowed_addresses: List[Address],
    allowed_ip_networks: List[ipaddress.IPv4Network],
) -> None:
    """Handle the incoming connection."""

    downstream_ip = downstream_writer.get_extra_info("peername")
    uuid = id(downstream_writer)
    LOG.debug("[%s] Incoming connection from %s:%s", uuid, *downstream_ip)

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(upstream.host, upstream.port),
            UPSTREAM_CONNECTION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        LOG.error("Failed to connect upstream: timed out")
        downstream_writer.close()
    except ConnectionRefusedError as err:
        LOG.error("Failed to connect upstream: connection refused")
        LOG.error(err.strerror)
        downstream_writer.close()
    except socket.gaierror as err:
        LOG.error(
            "Failed to connect upstream: unable to reach hostname %s", upstream.host
        )
        LOG.error(err.strerror)
        downstream_writer.close()
    except OSError as err:
        LOG.error(
            "Failed to connect upstream: probably trying to connect to an https server"
        )
        LOG.error(err.strerror)
        downstream_writer.close()
    else:
        # upstream connection established
        model = ProxyModel(
            uuid,
            allowed_addresses,
            allowed_ip_networks,
            downstream_reader,
            downstream_writer,
            upstream_reader,
            upstream_writer,
        )

        state = UndecidedFilterState(model)

        try:
            while state is not None:
                state = await state.next()
        except IOError:
            pass

    LOG.debug("[%s] Closed connection from %s:%s", uuid, *downstream_ip)


class ProxyModel:
    def __init__(
        self,
        uuid: int,
        allowed_addresses: List[Address],
        allowed_ip_networks: List[ipaddress.IPv4Network],
        downstream_reader: asyncio.StreamReader,
        downstream_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ):
        self.uuid = uuid
        self.allowed_addresses = allowed_addresses
        self.allowed_ip_networks = allowed_ip_networks
        self.downstream_reader = downstream_reader
        self.downstream_writer = downstream_writer
        self.upstream_reader = upstream_reader
        self.upstream_writer = upstream_writer

        # buffer used before we know if a connection is accepted or not
        self.buffered_lines: Deque[bytes] = deque()


class ProxyState:
    """Generic ProxyState that needs to be sub-classed."""

    def __init__(self, model: ProxyModel):
        self.model = model

    async def next(self) -> ProxyState | None:
        """Return the next State instance. Can be 'self'. Can also be None if there is nothing more
        to do."""

        raise NotImplementedError


class UndecidedFilterState(ProxyState):
    """Initial state: read from downstream but don't pass data upstram because we still don't know
    if the connection must be dropped or proxied. We still didn't reach the relevant http header
    line."""

    async def next(
        self,
    ) -> UndecidedFilterState | FilterPassState | FilterFailState | ConnectionClosingState:
        """Buffer incoming downstream data waiting for the proper http header line.

        Nginx must append relevant ip to the X-Forwarded-For header line. The real source ip must be
        the one directly connecting to nginx or the one coming from the proxy-protocol.

        E.g.:
        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;

        Or with proxy-protocol:
        listen <port> proxy_protocol;
        set_real_ip_from <trusted ip CIDR>;
        real_ip_header proxy_protocol;
        real_ip_recursive on;
        ...
        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        """

        downstream_line = b""
        if not self.model.downstream_reader.at_eof():
            try:
                downstream_line = await asyncio.wait_for(
                    self.model.downstream_reader.readline(), 1
                )
            except asyncio.TimeoutError:
                pass

        LOG.debug(
            '[%s] Received from downstream (buffering): "%s"',
            self.model.uuid,
            decode_data_for_logging(downstream_line),
        )

        self.model.buffered_lines.append(downstream_line)

        if downstream_line.startswith(b"X-Forwarded-For:"):
            real_ip = (
                downstream_line.split(b":")[1]
                .split(b",")[-1]
                .replace(b"\n", b"")
                .replace(b"\r", b"")
                .strip()
                .decode("utf-8")
            )

            # check by hostname
            for allowed_address in self.model.allowed_addresses:
                try:
                    allowed_hostname = allowed_address.host
                    allowed_ip = socket.gethostbyname(allowed_hostname)
                except socket.gaierror as err:
                    LOG.info(
                        "[%s] Unable to resolve allowed host %s",
                        self.model.uuid,
                        allowed_hostname,
                    )
                    LOG.info(err.strerror)
                else:
                    if real_ip == allowed_ip:
                        LOG.info("[%s] Real ip allowed: %s", self.model.uuid, real_ip)
                        return FilterPassState(self.model)

            # check by ip
            ip = ipaddress.ip_address(real_ip)
            for allowed_ip_network in self.model.allowed_ip_networks:
                if ip in allowed_ip_network:
                    LOG.info("[%s] Real ip allowed: %s", self.model.uuid, real_ip)
                    return FilterPassState(self.model)

            LOG.info("[%s] Real ip forbidden: %s", self.model.uuid, real_ip)
            return FilterFailState(self.model)
        elif downstream_line == b"":
            LOG.info(
                "[%s] Header not as expected: 'X-Forwarded-For' not found",
                self.model.uuid,
            )
            # read all data, but filter is still uncertain: fail by default
            return FilterFailState(self.model)
        else:
            return self


class FilterPassState(ProxyState):
    """Filter has decided: data can be passed upstream."""

    async def next(self) -> FilterPassState | TunnelUpstreamResponseState:
        """Flush upstream the buffer accumulated by UndecidedFilterState and keep proxying data from
        downstream to upstream."""

        while self.model.buffered_lines:
            LOG.debug(
                "[%s] Flushing buffer from downstream to upstream", self.model.uuid
            )
            self.model.upstream_writer.write(self.model.buffered_lines.popleft())

        await self.model.upstream_writer.drain()

        downstream_data = b""
        if not self.model.downstream_reader.at_eof():
            try:
                downstream_data = await asyncio.wait_for(
                    self.model.downstream_reader.read(BUFFER_LEN), 1
                )
            except asyncio.TimeoutError:
                pass
        LOG.debug(
            '[%s] Received from downstream and proxying upstream: "%s"',
            self.model.uuid,
            decode_data_for_logging(downstream_data),
        )

        if downstream_data != b"":
            self.model.upstream_writer.write(downstream_data)
            await self.model.upstream_writer.drain()

            # perhaps there is more to read and proxy upstream
            return self

        else:
            # EOF (or equivalent) reached
            self.model.upstream_writer.write_eof()
            return TunnelUpstreamResponseState(self.model)


class TunnelUpstreamResponseState(ProxyState):
    """Proxy upstream response."""

    async def next(self) -> TunnelUpstreamResponseState | ConnectionClosingState:
        """Read response from upstream and proxy it downstream."""

        upstream_data = b""
        if not self.model.upstream_reader.at_eof():
            try:
                upstream_data = await asyncio.wait_for(
                    self.model.upstream_reader.read(BUFFER_LEN), 1
                )
            except asyncio.TimeoutError:
                pass
        LOG.debug(
            '[%s] Received from upstream and proxying downstream: "%s"',
            self.model.uuid,
            decode_data_for_logging(upstream_data),
        )

        if upstream_data:
            self.model.downstream_writer.write(upstream_data)
            await self.model.downstream_writer.drain()

            # perhaps there is more to read and proxy downstream
            return self
        else:
            # EOF (or equivalent) reached
            self.model.downstream_writer.write_eof()
            await self.model.downstream_writer.drain()
            return ConnectionClosingState(self.model)


class FilterFailState(ProxyState):
    """Filter has decided: data can't be passed upstream."""

    async def next(self) -> ConnectionClosingState:
        """Drop downstream connection."""

        LOG.debug("[%s] Dropping downstream connection", self.model.uuid)

        self.model.downstream_writer.write(b"HTTP/1.1 444 NO RESPONSE\r\n\r\n")
        self.model.downstream_writer.write_eof()
        await self.model.downstream_writer.drain()

        return ConnectionClosingState(self.model)


class ConnectionClosingState(ProxyState):
    """Cleanup connections."""

    async def next(self) -> None:
        """Close upstream and downstream connections."""

        await asyncio.sleep(2)  # wait for writes to actually drain
        self.model.downstream_writer.close()
        self.model.upstream_writer.close()

        try:
            await self.model.downstream_writer.wait_closed()
        except ConnectionAbortedError:
            pass
        try:
            await self.model.upstream_writer.wait_closed()
        except ConnectionAbortedError:
            pass

        # nothing more to do
        return None


def decode_data_for_logging(data: bytes) -> str:
    """Decode the data, if possible, and shorten it in order to make log readable."""
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        decoded = "bytes that cannot be decoded to 'utf-8'"
    if len(decoded) > 60:
        decoded = decoded[:57] + "..."
    return decoded


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
