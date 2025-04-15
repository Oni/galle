from __future__ import annotations

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import asyncio
import logging
import signal
import ipaddress
from typing import Dict, List, Set, TypeGuard, Tuple, Coroutine
from functools import partial
import socket
import pathlib
import subprocess
from enum import Enum
import time
import json

from proxyprotocol.server import Address
from proxyprotocol.reader import ProxyProtocolReader
from proxyprotocol import ProxyProtocol, ProxyProtocolIncompleteError
from proxyprotocol.v1 import ProxyProtocolV1
from proxyprotocol.v2 import ProxyProtocolV2
from proxyprotocol.result import ProxyResult, ProxyResultIPv4, ProxyResultIPv6


LOG = logging.getLogger(__name__)
BUFFER_LEN = 1024
UPSTREAM_CONNECTION_TIMEOUT = 5  # seconds
CONTROL_CONNECTION_TIMEOUT = 5  # seconds
DNS_RESOLVE_TIMEOUT = 3  # seconds
DNS_CACHE_DURATION = 60  # seconds
BANNED_IPS: Set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()


class ProxyProtocolMode(Enum):
    NONE = 1
    PP_V1 = 2
    PP_V2 = 3


class ConnectionMode(Enum):
    TCP = 1
    UDP = 2


class AddressWithPort(Address):
    def __init__(self, address: str):
        super().__init__(address)

        if self.port is None:
            raise ValueError(f"Invalid address '{address}': port is missing")

    @property
    def port(self) -> int:
        port = super().port
        if port is None:
            raise ValueError("It's impossible to be here")
        else:
            return port


class General:
    def __init__(self, config: dict):
        try:
            log_level_s = config["log_level"]
        except KeyError as err:
            raise ValueError("Invalid config file: no 'log_level' option") from err

        try:
            log_level = {
                "error": logging.ERROR,
                "warn": logging.WARN,
                "info": logging.INFO,
                "debug": logging.DEBUG,
            }[log_level_s]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: 'log_level' option must be 'error', 'warn', 'info' or 'debug'"
            ) from err

        logging.basicConfig(
            level=log_level, format="%(asctime)-15s %(name)s %(message)s"
        )

        try:
            inactivity_timeout_s = config["inactivity_timeout"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: no 'inactivity_timeout_s' option"
            ) from err
        try:
            inactivity_timeout_f = float(inactivity_timeout_s)
        except ValueError as err:
            raise ValueError(
                "Invalid config file: the 'inactivity_timeout' must be an int or a float"
            ) from err
        if inactivity_timeout_f <= 0.0:
            raise ValueError(
                "Invalid config file: the 'inactivity_timeout' must be higher than 0"
            )
        self.inactivity_timeout = inactivity_timeout_f

        try:
            control_port_s = config["control_port"]
        except KeyError as err:
            raise ValueError("Invalid config file: no 'control_port' option") from err
        try:
            self.control_port = int(control_port_s)
        except ValueError as err:
            raise ValueError(
                "Invalid config file: the 'control_port' must be an int"
            ) from err

        try:
            dns_resolver = config["dns_resolver"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: no 'dns_resolver' option (but it can be empty)"
            ) from err
        self.resolver = Resolver(dns_resolver)


class Rule:
    def __init__(self, general: General, rule_config: dict):
        try:
            port_s = rule_config["port"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: no 'port' option found in rule"
            ) from err

        try:
            self.port = int(port_s)
        except ValueError as err:
            raise ValueError(
                f"Invalid config file: the port must be an int ('{port_s}' found instead)"
            ) from err

        try:
            self.name = rule_config["name"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: no 'name' option found in rule"
            ) from err

        available_modes = {
            "tcp": ConnectionMode.TCP,
            "udp": ConnectionMode.UDP,
        }
        try:
            mode_s = rule_config["mode"]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: missing 'mode' option in [{self.name}] rule"
            ) from err
        try:
            self.mode = available_modes[mode_s.lower()]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: 'mode' option in [{self.name}] rule must be one of 'tcp', "
                f"or 'udp' ('{mode_s}' found instead)"
            ) from err

        available_proxy_protocols = {
            "none": ProxyProtocolMode.NONE,
            "pp_v1": ProxyProtocolMode.PP_V1,
            "pp_v2": ProxyProtocolMode.PP_V2,
        }
        try:
            downstream_proxy_protocol_s = rule_config["from_downstream_proxy_protocol"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: missing 'from_downstream_proxy_protocol' option in "
                f"[{self.name}] rule"
            ) from err
        try:
            downstream_pp_mode = available_proxy_protocols[downstream_proxy_protocol_s]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: 'from_downstream_proxy_protocol' option in [{self.name}] "
                "rule must be one of 'none', 'pp_v1' or 'pp_v2' "
                f"('{downstream_proxy_protocol_s}' found instead)"
            ) from err
        if (
            self.mode == ConnectionMode.UDP
            and downstream_pp_mode == ProxyProtocolMode.PP_V1
        ):
            raise ValueError(
                "Invalid config file: 'from_downstream_proxy_protocol' "
                f"'{downstream_proxy_protocol_s}' works only in tcp "
                f"mode in [{self.name}] rule (as per Proxy Protocol V1 specification)"
            )
        self.downstream_pp: ProxyProtocol | None
        if downstream_pp_mode in (ProxyProtocolMode.PP_V1, ProxyProtocolMode.PP_V2):
            self.downstream_pp = {
                ProxyProtocolMode.PP_V1: ProxyProtocolV1,
                ProxyProtocolMode.PP_V2: ProxyProtocolV2,
            }[downstream_pp_mode]()
        else:
            self.downstream_pp = None

        try:
            upstream_proxy_protocol_s = rule_config["to_upstream_proxy_protocol"]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: missing 'to_upstream_proxy_protocol' option in "
                f"[{self.name}] rule"
            ) from err
        try:
            upstream_pp_mode = available_proxy_protocols[upstream_proxy_protocol_s]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: 'to_upstream_proxy_protocol' option in [{self.name}] rule "
                f"must be one of 'none', 'pp_v1' or 'pp_v2' ('{upstream_proxy_protocol_s}' found "
                "instead)"
            ) from err
        if (
            self.mode == ConnectionMode.UDP
            and upstream_pp_mode == ProxyProtocolMode.PP_V1
        ):
            raise ValueError(
                "Invalid config file: 'to_upstream_proxy_protocol' "
                f"'{upstream_proxy_protocol_s}' works only in tcp mode in [{self.name}] rule (as "
                "per Proxy Protocol V1 specification)"
            )
        self.upstream_pp: ProxyProtocol | None
        if upstream_pp_mode in (ProxyProtocolMode.PP_V1, ProxyProtocolMode.PP_V2):
            self.upstream_pp = {
                ProxyProtocolMode.PP_V1: ProxyProtocolV1,
                ProxyProtocolMode.PP_V2: ProxyProtocolV2,
            }[upstream_pp_mode]()
        else:
            self.upstream_pp = None

        # can be both None
        self.repeat_pp = type(self.downstream_pp) == type(self.upstream_pp)

        self.inactivity_timeout: float
        try:
            inactivity_timeout_s = rule_config["inactivity_timeout"]
        except KeyError as err:
            # use general default inactivity_timeout
            self.inactivity_timeout = general.inactivity_timeout
        else:
            try:
                inactivity_timeout_f = float(inactivity_timeout_s)
            except ValueError as err:
                raise ValueError(
                    f"Invalid config file: the 'inactivity_timeout' in [{self.name}] rule must be "
                    "an int or a float ('{inactivity_timeout_s}' found instead)"
                ) from err
            if inactivity_timeout_f <= 0.0:
                raise ValueError(
                    f"Invalid config file: the 'inactivity_timeout' in [{self.name}] rule must be "
                    "higher than 0 ('{inactivity_timeout_s}' found instead)"
                )
            self.inactivity_timeout = inactivity_timeout_f

        self.filters: List[Filter] = []
        for filter in rule_config.get("filters", []):
            self.filters.append(Filter(self.name, filter, general.resolver))

    def pick_upstream_and_log(
        self, source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, log_id: str
    ) -> Filter | None:
        if is_source_ip_blacklisted(source_ip):
            LOG.info("[%s] Real ip banned: %s", log_id, source_ip)
            return None
        else:
            for filter in self.filters:
                if filter.is_source_ip_allowed(source_ip):
                    LOG.info(
                        "[%s] Real ip allowed towards '%s': %s",
                        log_id,
                        pretty_hostname(filter.upstream),
                        source_ip,
                    )
                    return filter

            # no filter allowed the source ip
            LOG.info("[%s] Real ip forbidden: %s", log_id, source_ip)
            return None


class Filter:
    def __init__(self, name: str, filter_config: dict, resolver: Resolver):
        self.resolver = resolver

        try:
            self.upstream = AddressWithPort(filter_config["upstream"])
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: missing 'upstream' option in [{name}] rule"
            ) from err
        except ValueError as err:
            raise ValueError(
                f"Invalid config file: 'upstream' is missing the port in [{name}] rule"
            ) from err

        try:
            allowed_ns = [x.strip() for x in filter_config["allowed"]]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: missing 'allowed' option in [{name}] rule"
            ) from err
        allowed_s = [x for x in allowed_ns if x]
        if len(allowed_s) == 0:
            LOG.warning(
                "The 'allowed' option is empty in [%s] rule: blocking ALL traffic",
                name,
            )
        self.allow_all_connections = False
        self.allowed_ip_networks: List[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        self.allowed_addresses: List[Address] = []
        for address_or_ip_network_or_asterisk in allowed_s:
            if address_or_ip_network_or_asterisk == "*":
                self.allow_all_connections = True
                LOG.warning(
                    "The 'allowed' option in [%s] rule contains an '*': allowing ALL traffic",
                    name,
                )
            else:
                try:
                    self.allowed_ip_networks.append(
                        ipaddress.ip_network(address_or_ip_network_or_asterisk)
                    )
                except ValueError:
                    self.allowed_addresses.append(
                        Address(address_or_ip_network_or_asterisk)
                    )

    def is_source_ip_allowed(
        self,
        source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        # first: do we allow all connections? (fastest)
        if self.allow_all_connections:
            return True

        # second: check by ip (faster)
        for allowed_ip_network in self.allowed_ip_networks:
            if source_ip in allowed_ip_network:
                return True

        # third: check by hostname (slower)
        for allowed_address in self.allowed_addresses:
            allowed_hostname = allowed_address.host
            allowed_ip = self.resolver.resolve(allowed_hostname)
            if source_ip == allowed_ip:
                return True

        return False


class Resolver:
    """
    This object will resolve hostnames. Since we are resolving the same hostnames over and over, we
    cache the results for some time.

    At the moment is used for filtering incoming connections, not for resolving upstreams.
    """

    def __init__(self, dns_address: str):
        """
        The 'dns_address' can be empty. In that case, use the default system dns server.

        An explicit 'dns_address' is necessary if the system is using some sort of custom dns
        server, possibly with a slit horizon zone.
        """
        self.dns_address = dns_address
        self.cache: Dict[
            str, Tuple[float, ipaddress.IPv4Address | ipaddress.IPv6Address]
        ] = {}

    def resolve(
        self, hostname: str
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """
        Resolve hostname using system 'nslookup' command.
        """
        now = time.time()
        expiration, ip = self.cache.get(hostname, (0, None))
        if ip is not None and expiration < now:
            # Cache *was* valid, now it has expired!
            del self.cache[hostname]
            ip = None

        if ip is None:
            proc = subprocess.run(
                [
                    "nslookup",
                    f"-timeout={DNS_RESOLVE_TIMEOUT}",
                    f"{hostname}",
                    f"{self.dns_address}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            stdout, stderr = proc.stdout, proc.stderr
            if proc.returncode == 0:
                """
                The 'nslookup' command lists results as a series of 'Address:' lines. E.g.:
                Server:         1.1.1.1
                Address:        1.1.1.1:53

                Non-authoritative answer:
                Name:   www.google.com
                Address: 2a00:1450:4002:809::2004

                Non-authoritative answer:
                Name:   www.google.com
                Address: 142.251.209.4

                The useful one is at the bottom.
                """
                for line in reversed(stdout.splitlines()):
                    if line.startswith(b"Address:"):
                        ip_b = line.removeprefix(b"Address:").strip()
                        ip = ipaddress.ip_address(ip_b.decode("utf-8"))
                        # store in cache + return
                        self.cache[hostname] = (now + DNS_CACHE_DURATION, ip)
                        LOG.debug("Resolved %s to %s", hostname, ip)
                        return ip

                LOG.error("Unable to parse nslookup output: %s", stdout)
                return None

            else:
                LOG.error("The nslookup command returned non-0 result: %s", stderr)
                return None

        else:
            LOG.debug("Resolved (cached) %s to %s", hostname, ip)
            return ip


async def main() -> int:
    """
    The main function: gather() all servers listed in config.
    """
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
    try:
        with open(config_path, "r", encoding="utf-8") as json_data:
            config = json.loads(json_data.read())
            json_data.close()
    except FileNotFoundError:
        print(f"Unable to locate config file '{config_path}'")
        return 1

    try:
        general = General(config)
    except ValueError as err:
        print(err.args[0])
        return 1

    rules = []
    for rule in config.get("rules", []):
        try:
            rules.append(Rule(general, rule))
        except ValueError as err:
            print(err.args[0])
            return 1

    loop = asyncio.get_event_loop()
    forevers: List[asyncio.Task] = []
    for rule in rules:
        if rule.mode == ConnectionMode.TCP:
            try:
                server = await make_TCP_server(
                    rule,
                    general,
                )
            except OSError as err:
                LOG.error("Unable to run tcp proxy at local port %s", rule.port)
                LOG.error(err.strerror)
            else:
                forever = asyncio.create_task(server.serve_forever())
                LOG.info(
                    "Started serving tcp proxy at local port %s for rule named '%s'",
                    rule.port,
                    rule.name,
                )
                try:
                    loop.add_signal_handler(signal.SIGINT, forever.cancel)
                    loop.add_signal_handler(signal.SIGTERM, forever.cancel)
                except NotImplementedError:
                    # windows
                    pass

                forevers.append(forever)

        else:  # rule.mode = ConnectionMode.UDP
            try:
                await make_UDP_server(
                    loop,
                    rule,
                    general,
                )
            except OSError as err:
                LOG.error("Unable to run udp proxy at local port %s", rule.port)
                LOG.error(err.strerror)
            else:
                LOG.info(
                    "Started serving udp proxy at local port %s for rule named '%s'",
                    rule.port,
                    rule.name,
                )

    # init control listener
    if general.control_port != -1:
        try:
            control_listener = await make_control_listener(general.control_port)
        except OSError as err:
            LOG.error(
                "Unable to run control listener at local port %s", general.control_port
            )
            LOG.error(err.strerror)
        else:
            forever = asyncio.create_task(control_listener.serve_forever())
            LOG.info(
                "Started serving control listener at local port %s",
                general.control_port,
            )
            try:
                loop.add_signal_handler(signal.SIGINT, forever.cancel)
                loop.add_signal_handler(signal.SIGTERM, forever.cancel)
            except NotImplementedError:
                # windows
                pass

            forevers.append(forever)
    else:
        LOG.info("Skipping creation of control request listener")

    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    return 0


def make_TCP_server(
    rule: Rule,
    general: General,
) -> Coroutine:
    """
    Return a server that needs to be awaited.
    """

    address = Address(f"0.0.0.0:{rule.port}")
    proxy_partial = partial(
        proxy,
        rule=rule,
        general=general,
    )
    return asyncio.start_server(proxy_partial, address.host, address.port)


async def proxy(
    downstream_reader: asyncio.StreamReader,
    downstream_writer: asyncio.StreamWriter,
    rule: Rule,
    general: General,
) -> None:
    """
    Handle the incoming connection.
    """
    open_writers: tuple[asyncio.StreamWriter, ...] = (
        downstream_writer,
    )  # used to close them later

    downstream_ip_s, downstream_port = downstream_writer.get_extra_info("peername")
    uuid = id(downstream_writer)
    log_id = f"{uuid}|{rule.name}|{rule.port}"
    LOG.debug(
        "[%s] Incoming connection from %s:%s", log_id, downstream_ip_s, downstream_port
    )

    source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    if rule.downstream_pp is not None:
        header_reader = ProxyProtocolReader(rule.downstream_pp)
        try:
            downstream_pp_result = await header_reader.read(downstream_reader)
        except Exception as err:
            LOG.info(
                "[%s] Invalid PROXY protocol header",
                log_id,
            )
            LOG.info(err)
        else:
            if is_valid_ip_port(downstream_pp_result.source):
                source_ip, _ = downstream_pp_result.source
    else:
        source_ip = ipaddress.ip_address(downstream_ip_s)

    if source_ip is not None:
        filter = rule.pick_upstream_and_log(source_ip, log_id)

        if filter is not None:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(filter.upstream.host, filter.upstream.port),
                    UPSTREAM_CONNECTION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                LOG.error("Failed to connect upstream: timed out")
            except ConnectionRefusedError as err:
                LOG.error("Failed to connect upstream: connection refused")
                LOG.error(err.strerror)
            except socket.gaierror as err:
                LOG.error(
                    "Failed to connect upstream: unable to reach hostname %s",
                    filter.upstream.host,
                )
                LOG.error(err.strerror)
            except OSError as err:
                LOG.error(
                    "Failed to connect upstream: probably trying to connect to an https server"
                )
                LOG.error(err.strerror)
            else:
                open_writers += (upstream_writer,)
                if rule.upstream_pp is not None:
                    if rule.downstream_pp is not None and rule.repeat_pp:
                        # give for granted that the received PP is correct
                        upstream_writer.write(
                            rule.downstream_pp.pack(downstream_pp_result)
                        )
                        await upstream_writer.drain()
                    else:
                        (
                            destination_ip_s,
                            destination_port,
                        ) = downstream_writer.get_extra_info("sockname")
                        destination_ip = ipaddress.ip_address(destination_ip_s)

                        """
                        Important note: don't use 'downstream_ip' instead of 'source_ip' because, at
                        this point, the connection is considered to be coming from 'source_ip'.

                        Reminder: if there isn't a downstream proxy protocol, the 'downstream_ip'
                        and the 'source_ip' are the same.
                        """
                        upstream_pp_result: ProxyResultIPv4 | ProxyResultIPv6
                        protocol = socket.SOCK_STREAM
                        if isinstance(source_ip, ipaddress.IPv4Address) and isinstance(
                            destination_ip, ipaddress.IPv4Address
                        ):
                            upstream_pp_result = ProxyResultIPv4(
                                (source_ip, downstream_port),
                                (destination_ip, destination_port),
                                protocol=protocol,
                            )
                        elif isinstance(
                            source_ip, ipaddress.IPv6Address
                        ) and isinstance(destination_ip, ipaddress.IPv6Address):
                            upstream_pp_result = ProxyResultIPv6(
                                (source_ip, downstream_port),
                                (destination_ip, destination_port),
                                protocol=protocol,
                            )
                        else:
                            # it's 100% impossible to be here
                            raise ValueError(
                                "Incompatible source and destination ip version"
                            )

                        upstream_writer.write(rule.upstream_pp.pack(upstream_pp_result))
                        await upstream_writer.drain()

                inactivity_timeout = general.inactivity_timeout
                if rule.inactivity_timeout is not None:
                    inactivity_timeout = rule.inactivity_timeout
                """
                The idea here is to have a shared timeout among the pipes. Every time any pipe
                receives some data, the timeout is 'reset' and waits more time on both pipes.
                """
                timeout = InactivityTimeout(inactivity_timeout)

                forward_pipe = pipe(downstream_reader, upstream_writer, timeout)
                backward_pipe = pipe(upstream_reader, downstream_writer, timeout)
                await asyncio.gather(backward_pipe, forward_pipe)

                await asyncio.sleep(0.1)  # wait for writes to actually drain

    for writer in open_writers:
        if writer.can_write_eof():
            try:
                writer.write_eof()
            except OSError:  # Socket not connected
                pass  # we don't really care: connection is lost

        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    LOG.debug(
        "[%s] Closed connection from %s:%s", log_id, downstream_ip_s, downstream_port
    )


def is_valid_ip_port(
    source: str
    | tuple[ipaddress.IPv4Address, int]
    | tuple[ipaddress.IPv6Address, int]
    | None
) -> TypeGuard[Tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    """
    Provide a TypeGuard for ProxyProtocolReader.read() result.
    """
    return isinstance(source, tuple)


def is_source_ip_blacklisted(
    source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return source_ip in BANNED_IPS


def pretty_hostname(address: Address) -> str:
    str_address = str(address)
    if __debug__:
        assert str_address.startswith("//")
    return str_address[2:]


async def pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: InactivityTimeout,
) -> None:
    remaining_seconds = timeout.remaining
    while remaining_seconds and not reader.at_eof() and not writer.is_closing():
        try:
            writer.write(
                await asyncio.wait_for(reader.read(BUFFER_LEN), remaining_seconds)
            )
            timeout.awake()
        except asyncio.TimeoutError:
            # no problem, go on: check if our InactivityTimeout is ok
            pass
        except ConnectionResetError:
            # pipe is finished
            break

        remaining_seconds = timeout.remaining


class InactivityTimeout:
    """
    This Object handles shared pipe timeout.
    """

    def __init__(self, timeout: float):
        """
        The remaining time until timeout is prolonged every time we 'awake()' this
        InactivityTimeout.

        E.g. if we have t = InactivityTimeout(5), t.remaining should be around 5 seconds.
        If, after 3 seconds we query t.remaining again, we should get around 2 seconds.
        If we call t.awake() and we query t.remaining, it should be back again at around 5 seconds.
        """
        self.last_awake = time.time()
        self.timeout = timeout

    def awake(self) -> None:
        self.last_awake = time.time()

    @property
    def remaining(self) -> float:  # >= 0
        now = time.time()
        remaining = self.last_awake + self.timeout - now
        return max(remaining, 0)


def make_UDP_server(
    loop: asyncio.AbstractEventLoop,
    rule: Rule,
    general: General,
) -> Coroutine:
    """
    Return a server that needs to be awaited.
    """

    return loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(loop, rule, general),
        local_addr=("0.0.0.0", rule.port),
    )


class UDPServerProtocol(asyncio.DatagramProtocol):
    """
    This object controls connections coming from the downstream.

    The proxying logic will be in UDPProxyProtocol.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, rule: Rule, general: General):
        self.loop = loop
        self.rule = rule
        self.general = general

        self.downstream_transport: asyncio.DatagramTransport | None = None

    def connection_made(self, downstream_transport: asyncio.DatagramTransport):  # type: ignore[override]
        self.downstream_transport = downstream_transport

    def datagram_received(self, full_data: bytes, addr: Tuple[str, str]):  # type: ignore[override]
        downstream_ip, downstream_port = addr
        uuid = "datagram"
        log_id = f"{uuid}|{self.rule.name}|{self.rule.port}"
        LOG.debug(
            "[%s] Incoming connection from %s:%s",
            log_id,
            downstream_ip,
            downstream_port,
        )

        """
        Catch incoming data and extract the source ip: the real one or the one embedded in the PROXY
        protocol.
        """
        downstream_pp = self.rule.downstream_pp
        if isinstance(downstream_pp, ProxyProtocolV2):
            # make mypy happy, but downstream_pp can be either ProxyProtocolV2 on None for UDP
            try:
                # inspired by ProxyProtocolReader.read()
                header_data, payload_data = bytearray(), full_data
                while True:
                    try:
                        with memoryview(header_data) as view:
                            downstream_pp_result = downstream_pp.unpack(view)
                    except ProxyProtocolIncompleteError as exc:
                        want_read = exc.want_read
                        want_bytes = want_read.want_bytes
                        if (
                            want_bytes is not None
                            and want_bytes > 0
                            and want_bytes <= len(payload_data)
                        ):
                            header_data, payload_data = (
                                header_data + payload_data[:want_bytes],
                                payload_data[want_bytes:],
                            )
                        else:
                            raise ValueError(
                                "Incomplete PROXY protocol header"
                            ) from exc
                    else:
                        break

                data = payload_data
                if is_valid_ip_port(downstream_pp_result.source):
                    source_ip, _ = downstream_pp_result.source
            except Exception as err:
                LOG.info(
                    "[%s] Invalid PROXY protocol header",
                    log_id,
                )
                LOG.info(err)
        else:
            downstream_pp_result = None
            source_ip = ipaddress.ip_address(downstream_ip)
            data = full_data

        if source_ip is not None:
            filter = self.rule.pick_upstream_and_log(source_ip, log_id)

            if filter is not None:
                try:
                    self.loop.create_task(
                        self.loop.create_datagram_endpoint(
                            lambda: UDPProxyProtocol(
                                self,
                                log_id,
                                addr,
                                source_ip,
                                data,
                                downstream_pp_result,
                            ),
                            remote_addr=(filter.upstream.host, filter.upstream.port),
                        )
                    )
                except OSError as err:
                    LOG.error("Failed to connect upstream")
                    LOG.error(err.strerror)

    def error_received(self, err) -> None:
        LOG.debug("Error in datagram downstream: %s", err)


class UDPProxyProtocol(asyncio.DatagramProtocol):
    """
    This object is the actual proxy.
    """

    def __init__(
        self,
        udp_server_protocol: UDPServerProtocol,
        log_id: str,
        addr: Tuple[str, str],
        source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
        data: bytes,
        downstream_pp_result: ProxyResult | None,
    ):
        self.udp_server_protocol = (
            udp_server_protocol  # this holds all major connection information
        )
        self.log_id = log_id
        self.addr = addr
        self.source_ip = source_ip
        self.data = data
        self.downstream_pp_result = downstream_pp_result

        self.upstream_transport: asyncio.DatagramTransport | None = None
        self.timeout_handler: asyncio.TimerHandle | None = (
            None  # used for timing out this connection
        )

    def connection_made(self, upstream_transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.upstream_transport = upstream_transport

        udp_server_protocol = self.udp_server_protocol
        rule = udp_server_protocol.rule

        # pack the PROXY protocol header if needed
        if rule.upstream_pp is not None:
            if rule.downstream_pp is not None and rule.repeat_pp:
                if self.downstream_pp_result is not None:
                    # give for granted that the received PP is correct
                    full_data = (
                        rule.downstream_pp.pack(self.downstream_pp_result) + self.data
                    )
                else:
                    raise ValueError(
                        "downstream_pp_result is not None for sure at this point"
                    )
            else:
                (
                    destination_ip_s,
                    destination_port,
                ) = upstream_transport.get_extra_info("sockname")
                destination_ip = ipaddress.ip_address(destination_ip_s)

                upstream_pp_result: ProxyResultIPv4 | ProxyResultIPv6
                protocol = socket.SOCK_DGRAM
                if isinstance(self.source_ip, ipaddress.IPv4Address) and isinstance(
                    destination_ip, ipaddress.IPv4Address
                ):
                    upstream_pp_result = ProxyResultIPv4(
                        (
                            self.source_ip,
                            int(self.addr[1]),
                        ),
                        (destination_ip, destination_port),
                        protocol=protocol,
                    )
                elif isinstance(self.source_ip, ipaddress.IPv6Address) and isinstance(
                    destination_ip, ipaddress.IPv6Address
                ):
                    upstream_pp_result = ProxyResultIPv6(
                        (
                            self.source_ip,
                            int(self.addr[1]),
                        ),
                        (destination_ip, destination_port),
                        protocol=protocol,
                    )
                else:
                    # it's 100% impossible to be here
                    raise ValueError("Incompatible source and destination ip version")

                full_data = rule.upstream_pp.pack(upstream_pp_result) + self.data
        else:
            full_data = self.data

        # finally proxy downstream data to upstream
        self.upstream_transport.sendto(full_data)

    def datagram_received(self, data: bytes, addr: Tuple[str, str]) -> None:  # type: ignore[override]
        """
        Upstream responded: send the data back to the downstream.
        """
        if self.timeout_handler is not None:
            self.timeout_handler.cancel()

        udp_server_protocol = self.udp_server_protocol
        downstream_transport = udp_server_protocol.downstream_transport
        if downstream_transport is not None:
            # 100% sure that downstream_transport is not None
            downstream_transport.sendto(data, self.addr)
        loop = udp_server_protocol.loop
        self.timeout_handler = loop.call_later(
            udp_server_protocol.rule.inactivity_timeout,
            close_upstream_transport,
            self,
        )

    def error_received(self, err) -> None:
        LOG.debug("[%s] Error in datagram upstream: %s", self.log_id, err)

    def connection_lost(self, err) -> None:
        LOG.debug("[%s] Upstream connection lost: %s", self.log_id, err)


def close_upstream_transport(udp_proxy_protocol: UDPProxyProtocol) -> None:
    downstream_ip_s, downstream_port = udp_proxy_protocol.addr
    LOG.debug(
        "[%s] Closed connection from %s:%s",
        udp_proxy_protocol.log_id,
        downstream_ip_s,
        downstream_port,
    )
    upstream_transport = udp_proxy_protocol.upstream_transport
    if upstream_transport is not None:
        # 100% sure that upstream_transport is not None
        upstream_transport.close()


def decode_data_for_logging(data: bytes) -> str:
    """
    If log level is DEBUG, decode the data (if possible) and shorten it in order to make log
    readable. For performance, if the log level is lower, just provide a placeholder text.
    """

    if LOG.level == logging.DEBUG:
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            decoded = "bytes that cannot be decoded to 'utf-8'"
        if len(decoded) > 60:
            decoded = decoded[:57] + "..."
        return decoded
    else:
        return "<some data>"


class HeaderBeforeContentLength:
    """
    A state machine for simple HTTP parsing.

    HeaderBeforeContentLength step: the beginning of our parsing. We are reading the HTTP header
    waiting for the 'Content-Length: <something>\n' line.
    """

    def __init__(self):
        self.data = b""

    def consume(
        self, data: bytes
    ) -> HeaderBeforeContentLength | HeaderAfterContentLength | Body | CompletedBody:
        """
        Look for the 'Content-Length: <something>\n' line and discard everything else.
        """

        self.data += data

        while True:
            try:
                parsable_data, self.data = self.data.split(b"\r\n", 1)
            except ValueError:
                return self

            if parsable_data.startswith(b"Content-Length:"):
                content_length_b = (
                    parsable_data.replace(b"Content-Length:", b"")
                    .replace(b"\r\n", b"")
                    .strip()
                )
                try:
                    content_length = int(content_length_b)
                except ValueError:
                    return self
                else:
                    next = HeaderAfterContentLength(content_length)
                    return next.consume(self.data)


class HeaderAfterContentLength:
    """
    A state machine for simple HTTP parsing.

    HeaderAfterContentLength step: we are reading the HTTP header and discarding everything until
    the body of the request is found.
    """

    def __init__(self, content_length):
        self.data = b""
        self.content_length = content_length

    def consume(self, data: bytes) -> HeaderAfterContentLength | Body | CompletedBody:
        """
        Discard everything until the empty line is found.
        """

        self.data += data

        while True:
            try:
                parsable_data, self.data = self.data.split(b"\r\n", 1)
            except ValueError:
                return self

            if parsable_data == b"":
                next = Body(self.content_length)
                return next.consume(self.data)


class Body:
    """
    A state machine for simple HTTP parsing.

    Body step: we are reading and storing the HTTP body.
    """

    def __init__(self, content_length: int):
        self.data = b""
        self.content_length = content_length

    def consume(self, data: bytes) -> Body | CompletedBody:
        """
        Store everything until all 'content_length' bytes are consumed.
        """

        self.data += data
        if len(self.data) < self.content_length:
            return self
        else:
            return CompletedBody(self.data)


class CompletedBody:
    """
    A state machine for simple HTTP parsing.

    CompletedBody step: we are done reading the body. The parsing is over.
    """

    def __init__(self, data: bytes):
        decoded_data = data.decode("utf-8", errors="replace")
        name_values = decoded_data.split("&")
        self.vars = {}
        for name_value in name_values:
            try:
                name, value = name_value.split("=")
            except ValueError:
                continue
            self.vars[name] = value

    def consume(self, data: bytes) -> CompletedBody:
        """
        We should never reach this point.
        """
        raise ValueError("Can't add data to a CompletedBody")


def make_control_listener(
    listening_port: int,
) -> Coroutine:
    address = Address(f"0.0.0.0:{listening_port}")
    return asyncio.start_server(control, address.host, address.port)


async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Listen for an HTTP request for controlling galle.

    See README for accepted commands.
    """

    LOG.debug("Control connection incoming")
    status: HeaderBeforeContentLength | HeaderAfterContentLength | Body | CompletedBody = (
        HeaderBeforeContentLength()
    )
    while not reader.at_eof():
        try:
            data = await asyncio.wait_for(
                reader.read(BUFFER_LEN), CONTROL_CONNECTION_TIMEOUT
            )
        except asyncio.TimeoutError:
            LOG.error("Control connection timed out")
            break
        status = status.consume(data)

        if isinstance(status, CompletedBody):
            break

    if isinstance(status, CompletedBody):
        verb = status.vars.get("verb", "")
        if verb == "ban_set":
            LOG.info("Control connection asked for 'ban_set'")
            ips = status.vars.get("ips", "").split("-")
            global BANNED_IPS
            try:
                ip_networks = [
                    ipaddress.ip_network(x.replace("%2F", "/").replace("%3A", ":"))
                    for x in ips
                ]
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad Request")
                LOG.info("Control [ban_set]: wrongly formatted ips")
            else:
                writer.write(b"HTTP/1.1 200 OK")
                BANNED_IPS = set()
                for ip_network in ip_networks:
                    BANNED_IPS |= set(ip_network.hosts())

                LOG.info(
                    "Control [ban_set]: new 'BANNED_IPS' has %s items", len(BANNED_IPS)
                )
        else:
            writer.write(b"HTTP/1.1 400 Bad Request")
            LOG.info("Control invalid verb: '%s'", verb)
    else:
        writer.write(b"HTTP/1.1 408 Request Timeout")
        LOG.info("Control timed out")

    writer.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
