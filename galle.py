from __future__ import annotations

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import asyncio
import logging
import signal
import ipaddress
from typing import List, Set, TypeGuard, Tuple, Coroutine
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
CONTROL_CONNECTION_TIMEOUT = 5  # seconds
BANNED_IPS: Set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()


class Mode(Enum):
    PP_V1 = 1
    PP_V2 = 2


class General:
    def __init__(self, config: configparser.ConfigParser):
        try:
            log_level_s = config.get("general", "log_level")
        except configparser.NoSectionError as err:
            raise ValueError("Invalid config file: no [general] section") from err
        except configparser.NoOptionError as err:
            raise ValueError(
                "Invalid config file: no 'log_level' option in [general] section"
            ) from err

        try:
            log_level = {
                "error": logging.ERROR,
                "warn": logging.WARN,
                "info": logging.INFO,
                "debug": logging.DEBUG,
            }[log_level_s]
        except KeyError as err:
            raise ValueError(
                "Invalid config file: 'log_level' option in [general] section must be 'error', "
                "'warn', 'info' or 'debug'"
            ) from err

        logging.basicConfig(
            level=log_level, format="%(asctime)-15s %(name)s %(message)s"
        )

        try:
            inactivity_timeout_s = config.get("general", "inactivity_timeout")
            # configparser.NoSectionError eventually raised by previous option query
        except configparser.NoOptionError as err:
            raise ValueError(
                "Invalid config file: no 'inactivity_timeout' option in [general] section"
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
            control_port_s = config.get("general", "control_port")
            # configparser.NoSectionError eventually raised by previous option query
        except configparser.NoOptionError:
            raise ValueError(
                "Invalid config file: no 'control_port' option in [general] section"
            )
        try:
            self.control_port = int(control_port_s)
        except ValueError:
            raise ValueError("Invalid config file: the 'control_port' must be an int")


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

        self.inactivity_timeout: float | None
        try:
            inactivity_timeout_s = config.get(section, "inactivity_timeout")
        except configparser.NoOptionError as err:
            self.inactivity_timeout = None
        else:
            try:
                inactivity_timeout_f = float(inactivity_timeout_s)
            except ValueError as err:
                raise ValueError(
                    f"Invalid config file: the 'inactivity_timeout' in [{section}] section must be "
                    "an int or a float"
                ) from err
            if inactivity_timeout_f <= 0.0:
                raise ValueError(
                    f"Invalid config file: the 'inactivity_timeout' in [{section}] sectionmust be "
                    "higher than 0"
                )
            self.inactivity_timeout = inactivity_timeout_f

        try:
            self.upstream = Address(config.get(section, "upstream"))
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'upstream' option in [{section}] section"
            ) from err

        try:
            allowed_ns = [x.strip() for x in config.get(section, "allowed").split(",")]
        except configparser.NoOptionError as err:
            raise ValueError(
                f"Invalid config file: missing 'allowed' option in [{section}] section"
            ) from err
        allowed_s = [x for x in allowed_ns if x]
        if len(allowed_s) == 0:
            LOG.warning(
                "The 'allowed' option is empty in [%s] section: blocking ALL traffic",
                section,
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
                    "The 'allowed' option in [%s] section contains an '*': allowing ALL traffic",
                    section,
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
        general = General(config)
    except ValueError as err:
        print(err.args[0])
        return 1

    rules = []
    for section in [x for x in config.sections() if x != "general"]:
        try:
            rules.append(Rule(config, section))
        except ValueError as err:
            print(err.args[0])
            return 1

    loop = asyncio.get_event_loop()
    forevers = []
    for rule in rules:
        try:
            server = await make_server(
                rule,
                general,
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
    else:
        LOG.info("Skipping creation of control request listener")

    try:
        await asyncio.gather(*forevers)
    except asyncio.CancelledError:
        pass
    return 0


def make_server(
    rule: Rule,
    general: General,
) -> Coroutine:
    """Return a server that needs to be awaited."""

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
            if is_source_ip_blacklisted(source_ip):
                LOG.info("[%s] Real ip banned: %s", log_id, source_ip)
                target_upstream = None  # always drop banned ips
            elif rule.is_source_ip_allowed(source_ip):
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

                    inactivity_timeout = general.inactivity_timeout
                    if rule.inactivity_timeout is not None:
                        inactivity_timeout = rule.inactivity_timeout
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
