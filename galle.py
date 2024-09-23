from __future__ import annotations

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import asyncio
import logging
import signal
import ipaddress
from typing import List, TypeGuard, Tuple, Coroutine
from functools import partial
import socket
import pathlib
import configparser
from enum import Enum
import time

from proxyprotocol.server import Address
from proxyprotocol.reader import ProxyProtocolReader
from proxyprotocol import ProxyProtocol
from proxyprotocol.v1 import ProxyProtocolV1
from proxyprotocol.v2 import ProxyProtocolV2


LOG = logging.getLogger(__name__)
BUFFER_LEN = 1024
UPSTREAM_CONNECTION_TIMEOUT = 5  # seconds


class Mode(Enum):
    PP_V1 = 1
    PP_V2 = 2


class Rule:
    def __init__(self, config: configparser.ConfigParser, section: str):
        try:
            self.port = int(section)
        except ValueError as err:
            raise ValueError(
                "Invalid config file: the section name (the port we want to listen "
                "to) must be an int"
            ) from err

        available_modes = {
            "pp_v1": Mode.PP_V1,
            "pp_v2": Mode.PP_V2,
        }
        try:
            mode_s = config.get(section, "mode")
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'mode' option in [{section}] section"
            ) from err
        try:
            self.pp_mode = available_modes[mode_s]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: 'mode' option in [{section}] section must be one of 'pp_v1' "
                "or 'pp_v2'"
            ) from err

        self.reject_upstream: Address | None
        try:
            reject_action = config.get(section, "on_reject")
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'on_reject' option in [{section}] section"
            ) from err
        if reject_action.lower() == "drop":
            self.reject_upstream = None
        else:
            if not reject_action.lower().startswith("redirect:"):
                raise ValueError(
                    f"Invalid config file: 'on_reject' option in [{section}] section must be "
                    "'drop' or 'redirect:<some_upstream>'"
                )
            else:
                reject_upstream_s = (
                    reject_action.lower().replace("redirect:", "", 1).strip()
                )
                if not reject_upstream_s:
                    raise ValueError(
                        f"Invalid config file: 'on_reject' option in [{section}] section has an "
                        "empty upstream. Use 'drop' if you want to drop the rejected connections"
                    )
                self.reject_upstream = Address(reject_upstream_s)

        try:
            repeat_s = config.get(section, "repeat")
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'repeat' option in [{section}] section"
            ) from err
        try:
            self.repeat_pp = {"true": True, "false": False}[repeat_s.lower()]
        except KeyError as err:
            raise ValueError(
                f"Invalid config file: 'repeat' option in [{section}] section must be 'true' or "
                "'false'"
            ) from err

        try:
            self.upstream = Address(config.get(section, "upstream"))
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'upstream' option in [{section}] section"
            ) from err

        try:
            allowed_hosts = [
                x.strip() for x in config.get(section, "allowed_hosts").split(",")
            ]
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'allowed_hosts' option in [{section}] section"
            ) from err

        try:
            allowed_ips = [
                x.strip() for x in config.get(section, "allowed_ips").split(",")
            ]
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'allowed_ips' option in [{section}] section"
            ) from err

        self.allowed_addresses = [Address(x) for x in allowed_hosts]
        self.allowed_ip_networks: List[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        for allowed_ip in allowed_ips:
            try:
                self.allowed_ip_networks.append(ipaddress.ip_network(allowed_ip))
            except ValueError as err:
                raise ValueError(
                    f"Unable to translate {allowed_ip} to a valid ip range in [{section}] section"
                ) from err

    def is_source_ip_allowed(
        self,
        source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        # first: check by ip (faster)
        for allowed_ip_network in self.allowed_ip_networks:
            if source_ip in allowed_ip_network:
                return True

        # second: check by hostname (slower)
        for allowed_address in self.allowed_addresses:
            try:
                allowed_hostname = allowed_address.host
                allowed_ip = ipaddress.ip_address(
                    socket.gethostbyname(allowed_hostname)
                )
            except socket.gaierror as err:
                LOG.info(
                    "Unable to resolve allowed host %s",
                    allowed_hostname,
                )
                LOG.info(err.strerror)
            else:
                if source_ip == allowed_ip:
                    return True

        return False


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
        log_level_s = config.get("general", "log_level")
    except configparser.NoSectionError:
        print("Invalid config file: no [general] section")
        return 1
    except configparser.NoOptionError:
        print("Invalid config file: no 'log_level' option in [general] section")
        return 1

    try:
        log_level = {
            "error": logging.ERROR,
            "warn": logging.WARN,
            "info": logging.INFO,
            "debug": logging.DEBUG,
        }[log_level_s]
    except KeyError:
        print(
            "Invalid config file: 'log_level' option in [general] section must be 'error', 'warn', "
            "'info' or 'debug'"
        )
        return 1

    logging.basicConfig(level=log_level, format="%(asctime)-15s %(name)s %(message)s")

    try:
        inactivity_timeout_s = config.get("general", "inactivity_timeout")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        print(
            "Invalid config file: no 'inactivity_timeout' option in [general] section"
        )
        return 1
    try:
        inactivity_timeout = float(inactivity_timeout_s)
    except ValueError:
        print("Invalid config file: the 'inactivity_timeout' must be an int or a float")
        return 1

    rules = []
    for section in [x for x in config.sections() if x != "general"]:
        try:
            rules.append(Rule(config, section))
        except ValueError as e:
            print(e.args[0])
            return 1

    loop = asyncio.get_event_loop()
    forevers = []
    for rule in rules:
        try:
            server = await make_server(
                rule,
                inactivity_timeout,
            )
        except OSError as err:
            LOG.error("Unable to run tcp proxy at local port %s", rule.port)
            LOG.error(err.strerror)
        else:
            forever = asyncio.create_task(server.serve_forever())
            LOG.info(
                "Started serving tcp proxy at local port %s that will forward traffic to %s",
                rule.port,
                pretty_hostname(rule.upstream),
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
    rule: Rule,
    inactivity_timeout: float,
) -> Coroutine:
    """Return a server that needs to be awaited."""

    address = Address(f"0.0.0.0:{rule.port}")
    proxy_partial = partial(
        proxy,
        rule=rule,
        inactivity_timeout=inactivity_timeout,
    )
    return asyncio.start_server(proxy_partial, address.host, address.port)


async def proxy(
    downstream_reader: asyncio.StreamReader,
    downstream_writer: asyncio.StreamWriter,
    rule: Rule,
    inactivity_timeout: float,
) -> None:
    """Handle the incoming connection."""
    open_writers: tuple[asyncio.StreamWriter, ...] = (
        downstream_writer,
    )  # used to close them later

    downstream_ip = downstream_writer.get_extra_info("peername")
    uuid = id(downstream_writer)
    log_id = f"{uuid}|{rule.port}|{pretty_hostname(rule.upstream)}"
    LOG.debug("[%s] Incoming connection from %s:%s", log_id, *downstream_ip)

    pp: ProxyProtocol = {
        Mode.PP_V1: ProxyProtocolV1,
        Mode.PP_V2: ProxyProtocolV2,
    }[rule.pp_mode]()

    header_reader = ProxyProtocolReader(pp)
    try:
        pp_result = await header_reader.read(downstream_reader)
    except Exception as err:
        LOG.info(
            "[%s] Invalid PROXY protocol header",
            log_id,
        )
        LOG.info(err)
    else:
        if is_valid_ip_port(pp_result.source):
            source_ip, _ = pp_result.source
            if rule.is_source_ip_allowed(source_ip):
                LOG.info("[%s] Real ip allowed: %s", log_id, source_ip)
                target_upstream = rule.upstream
            else:
                if rule.reject_upstream is None:
                    LOG.info("[%s] Real ip forbidden (drop): %s", log_id, source_ip)
                    target_upstream = None
                else:
                    LOG.info(
                        "[%s] Real ip forbidden (redirect to %s): %s",
                        log_id,
                        pretty_hostname(rule.reject_upstream),
                        source_ip,
                    )
                    target_upstream = rule.reject_upstream

            if target_upstream is not None:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            target_upstream.host, target_upstream.port
                        ),
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
                        rule.upstream.host,
                    )
                    LOG.error(err.strerror)
                except OSError as err:
                    LOG.error(
                        "Failed to connect upstream: probably trying to connect to an https server"
                    )
                    LOG.error(err.strerror)
                else:
                    open_writers += (upstream_writer,)
                    if rule.repeat_pp:
                        upstream_writer.write(pp.pack(pp_result))
                        await upstream_writer.drain()

                    """The idea here is to have a shared timeout among the pipes. Every time any
                    pipe receives some data, the timeout is 'reset' and waits more time on both
                    pipes.
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
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    LOG.debug("[%s] Closed connection from %s:%s", log_id, *downstream_ip)


def is_valid_ip_port(
    source: str
    | tuple[ipaddress.IPv4Address, int]
    | tuple[ipaddress.IPv6Address, int]
    | None
) -> TypeGuard[Tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    """Provide a TypeGuard for ProxyProtocolReader.read() result."""
    return isinstance(source, tuple)


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
    while remaining_seconds and not reader.at_eof():
        try:
            writer.write(
                await asyncio.wait_for(reader.read(BUFFER_LEN), remaining_seconds)
            )
            timeout.awake()
        except asyncio.TimeoutError:
            pass

        remaining_seconds = timeout.remaining


class InactivityTimeout:
    """
    This Object handles shared pipe timeout.
    """

    def __init__(self, timeout):
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


def decode_data_for_logging(data: bytes) -> str:
    """If log level is DEBUG, decode the data (if possible) and shorten it in order to make log
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


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
