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
BANNED_IPS: List[BannedIp] = []  # global list of banned ips


class Mode(Enum):
    PP_V1 = 1
    PP_V2 = 2


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

    try:
        ban_requests_port_s = config.get("general", "ban_requests_port")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        print("Invalid config file: no 'ban_requests_port' option in [general] section")
        return 1
    try:
        ban_requests_port = int(ban_requests_port_s)
    except ValueError:
        print("Invalid config file: the 'ban_requests_port' must be an int")
        return 1

    configs = []
    for section in [x for x in config.sections() if x != "general"]:
        try:
            listening_port = int(section)
        except ValueError:
            print(
                "Invalid config file: the section name (the port we want to listen to) must be an "
                "int"
            )
            return 1

        available_modes = {
            "pp_v1": Mode.PP_V1,
            "pp_v2": Mode.PP_V2,
        }
        try:
            mode_s = config.get(section, "mode")
        except configparser.NoOptionError:
            print(f"Invalid config file: missing 'mode' option in [{section}] section")
            return 1
        try:
            mode = available_modes[mode_s]
        except KeyError:
            print(
                f"Invalid config file: 'mode' option in [{section}] section must be one of 'pp_v1' "
                "or 'pp_v2'"
            )
            return 1

        try:
            reject_action = config.get(section, "on_reject")
        except configparser.NoOptionError:
            print(
                f"Invalid config file: missing 'on_reject' option in [{section}] section"
            )
            return 1
        if reject_action.lower() == "drop":
            reject_upstream = ""
        else:
            if not reject_action.lower().startswith("redirect:"):
                print(
                    f"Invalid config file: 'on_reject' option in [{section}] section must be "
                    "'drop' or 'redirect:<some_upstream>'"
                )
                return 1
            else:
                reject_upstream = (
                    reject_action.lower().replace("redirect:", "", 1).strip()
                )
                if not reject_upstream:
                    print(
                        f"Invalid config file: 'on_reject' option in [{section}] section has an "
                        "empty upstream. Use 'drop' if you want to drop the rejected connections"
                    )
                    return 1

        try:
            repeat_s = config.get(section, "repeat")
        except configparser.NoOptionError:
            print(
                f"Invalid config file: missing 'repeat' option in [{section}] section"
            )
            return 1
        try:
            repeat = {"true": True, "false": False}[repeat_s.lower()]
        except KeyError:
            print(
                f"Invalid config file: 'repeat' option in [{section}] section must be 'true' or "
                "'false'"
            )
            return 1

        try:
            upstream = config.get(section, "upstream")
        except configparser.NoOptionError:
            print(
                f"Invalid config file: missing 'upstream' option in [{section}] section"
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

        configs.append(
            (
                mode,
                repeat,
                upstream,
                reject_upstream,
                listening_port,
                allowed_hosts,
                allowed_ips,
            )
        )

    loop = asyncio.get_event_loop()
    forevers = []

    # init proxies
    for (
        mode,
        repeat,
        upstream,
        reject_upstream,
        listening_port,
        allowed_hosts,
        allowed_ips,
    ) in configs:
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
                Address(reject_upstream) if reject_upstream else None,
                mode,
                repeat,
                allowed_addresses,
                allowed_ip_networks,
                inactivity_timeout,
            )
        except OSError as err:
            LOG.error("Unable to run tcp proxy at local port %s", listening_port)
            LOG.error(err.strerror)
        else:
            forever = asyncio.create_task(server.serve_forever())
            LOG.info(
                "Started serving tcp proxy at local port %s that will forward traffic to %s",
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

    # init ban request listener
    if ban_requests_port != -1:
        try:
            ban_listener = await make_ban_listener(ban_requests_port)
        except OSError as err:
            LOG.error(
                "Unable to run ban request listener at local port %s", ban_requests_port
            )
            LOG.error(err.strerror)
        else:
            forever = asyncio.create_task(ban_listener.serve_forever())
            LOG.info("Started serving ban listener at local port %s", ban_requests_port)
            try:
                loop.add_signal_handler(signal.SIGINT, forever.cancel)
                loop.add_signal_handler(signal.SIGTERM, forever.cancel)
            except NotImplementedError:
                # windows
                pass
    else:
        LOG.info("Skipping creation of ban request listener")

    try:
        await asyncio.gather(*forevers)
    except asyncio.CancelledError:
        pass
    return 0


def make_server(
    listening_port: int,
    upstream: Address,
    reject_upstream: Address | None,
    mode: Mode,
    repeat: bool,
    allowed_addresses: List[Address],
    allowed_ip_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network],
    inactivity_timeout: float,
) -> Coroutine:
    """Return a server that needs to be awaited."""

    address = Address(f"0.0.0.0:{listening_port}")
    proxy_partial = partial(
        proxy,
        listening_port=listening_port,
        upstream=upstream,
        reject_upstream=reject_upstream,
        mode=mode,
        repeat=repeat,
        allowed_addresses=allowed_addresses,
        allowed_ip_networks=allowed_ip_networks,
        inactivity_timeout=inactivity_timeout,
    )
    return asyncio.start_server(proxy_partial, address.host, address.port)


async def proxy(
    downstream_reader: asyncio.StreamReader,
    downstream_writer: asyncio.StreamWriter,
    listening_port: int,
    upstream: Address,
    reject_upstream: Address | None,
    mode: Mode,
    repeat: bool,
    allowed_addresses: List[Address],
    allowed_ip_networks: List[ipaddress.IPv4Network],
    inactivity_timeout: float,
) -> None:
    """Handle the incoming connection."""
    open_writers: tuple[asyncio.StreamWriter, ...] = (
        downstream_writer,
    )  # used to close them later

    downstream_ip = downstream_writer.get_extra_info("peername")
    uuid = id(downstream_writer)
    log_id = f"{uuid}|{listening_port}|{pretty_hostname(upstream)}"
    LOG.debug("[%s] Incoming connection from %s:%s", log_id, *downstream_ip)

    pp: ProxyProtocol = {
        Mode.PP_V1: ProxyProtocolV1,
        Mode.PP_V2: ProxyProtocolV2,
    }[mode]()

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

            # drop banned ips
            for banned_ip in BANNED_IPS[
                :
            ]:  # make a copy: we change BANNED_IPS as we go
                if not banned_ip.still_banned():
                    BANNED_IPS.remove(banned_ip)
                    LOG.info(
                        "Lifting ban for %s (expired at %s)",
                        banned_ip.ip,
                        banned_ip.formatted_ban_end_time(),
                    )
                    continue
                else:
                    if source_ip == banned_ip.ip:
                        LOG.info("[%s] Real ip banned: %s", log_id, source_ip)
                        target_upstream = None
                        break
            else:
                # break never occurred: check the whitelist

                if is_source_ip_allowed(
                    source_ip, allowed_addresses, allowed_ip_networks
                ):
                    LOG.info("[%s] Real ip allowed: %s", log_id, source_ip)
                    target_upstream = upstream
                else:
                    if reject_upstream is None:
                        LOG.info("[%s] Real ip forbidden (drop): %s", log_id, source_ip)
                        target_upstream = None
                    else:
                        LOG.info(
                            "[%s] Real ip forbidden (redirect to %s): %s",
                            log_id,
                            pretty_hostname(reject_upstream),
                            source_ip,
                        )
                        target_upstream = reject_upstream

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
                        upstream.host,
                    )
                    LOG.error(err.strerror)
                except OSError as err:
                    LOG.error(
                        "Failed to connect upstream: probably trying to connect to an https server"
                    )
                    LOG.error(err.strerror)
                else:
                    open_writers += (upstream_writer,)
                    if repeat:
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

    for open_writer in open_writers:
        await close_write_stream(open_writer)

    LOG.debug("[%s] Closed connection from %s:%s", log_id, *downstream_ip)


def make_ban_listener(
    listening_port: int,
) -> Coroutine:
    address = Address(f"0.0.0.0:{listening_port}")
    return asyncio.start_server(process_ban_request, address.host, address.port)


async def process_ban_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Given a connection, try to parse it into a proper ban. Write back an empty response in the
    write stream.
    """

    ban_request = await read_ban_request(reader)
    if ban_request:
        banned_ip = ban_request_to_banned_ip(ban_request)
        if banned_ip is not None:
            BANNED_IPS.append(banned_ip)
            LOG.info(
                "Ban request accepted for ip %s until %s",
                banned_ip.ip,
                banned_ip.formatted_ban_end_time(),
            )

    await close_write_stream(writer)


async def read_ban_request(reader: asyncio.StreamReader) -> str:
    """Read the stream and return the very last line (stripped). The expected data is:
    <HTTP header stuff here: ignored>
    <empty line>
    <last line that will be returned stripped>

    If anything fails, return an empty string.
    """
    data = b""
    try:
        while not reader.at_eof():
            data += await asyncio.wait_for(
                reader.read(BUFFER_LEN), UPSTREAM_CONNECTION_TIMEOUT
            )
            if data.endswith(b"EOF"):
                break
    except asyncio.TimeoutError:
        pass

    try:
        request = data.decode("utf-8")
    except UnicodeDecodeError:
        LOG.error("Could not decode ban request in UTF-8")
        return ""

    request_lines = request.splitlines()

    try:
        if request_lines[-2].strip() != "":
            LOG.error(
                "Badly formatted ban request: request body is empty or has too many lines"
            )
            return ""
    except IndexError:
        LOG.error("Badly formatted ban request: not enough lines")
        return ""

    return request_lines[-1].strip()


def ban_request_to_banned_ip(ban_request: str) -> BannedIp | None:
    """Given a ban request, translate it to a BannedIp object if possible. We expect a string like:
    <ip to ban, v4 or v6> <ban duration as an int, in seconds><possibly a space>EOF

    If anything fails, return None.
    """

    if not ban_request.endswith("EOF"):
        LOG.error("Ban request '%s' doesn't end with 'EOF' string", ban_request)
        return None

    try:
        ip_to_ban_s, ban_duration_s = ban_request[
            :-3
        ].split()  # -3 because we cut 'EOF'
    except ValueError:
        LOG.error("Could not unpack ban request '%s'", ban_request)
        return None

    try:
        ip_to_ban = ipaddress.ip_address(ip_to_ban_s)
    except ValueError:
        LOG.error("Invalid ip '%s'", ip_to_ban_s)
        return None

    try:
        ban_duration = int(ban_duration_s)
    except ValueError:
        LOG.error("Invalid duration '%s'", ban_duration_s)
        return None

    ban_end_time = time.time() + ban_duration
    return BannedIp(ip_to_ban, ban_end_time)


async def close_write_stream(writer: asyncio.StreamWriter) -> None:
    """Gracefully close the writer stream."""
    if writer.can_write_eof():
        try:
            writer.write_eof()
        except OSError:  # Socket not connected
            pass  # connection is lost, but we don't really care

    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionAbortedError, BrokenPipeError):
        pass


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


def is_source_ip_allowed(
    source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowed_addresses: List[Address],
    allowed_ip_networks: List[ipaddress.IPv4Network],
) -> bool:
    # check by hostname
    for allowed_address in allowed_addresses:
        try:
            allowed_hostname = allowed_address.host
            allowed_ip = ipaddress.ip_address(socket.gethostbyname(allowed_hostname))
        except socket.gaierror as err:
            LOG.info(
                "Unable to resolve allowed host %s",
                allowed_hostname,
            )
            LOG.info(err.strerror)
        else:
            if source_ip == allowed_ip:
                return True

    # check by ip
    for allowed_ip_network in allowed_ip_networks:
        if source_ip in allowed_ip_network:
            return True

    return False


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


class BannedIp:
    """
    This object wraps an ip ban.
    """

    def __init__(
        self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, ban_end_time: float
    ):
        self.ip = ip
        self._ban_end_time = ban_end_time

    def still_banned(self) -> bool:
        now = time.time()
        return now < self._ban_end_time

    def formatted_ban_end_time(self) -> str:
        local_time = time.localtime(self._ban_end_time)
        return time.strftime("%Y-%m-%d %H:%M:%S", local_time)


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
