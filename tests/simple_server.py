import asyncio
import logging
import ssl
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, socket
from ssl import SSLSocket
from typing import Optional, Tuple

from dtls import do_patch

do_patch()
logger = logging.getLogger(__name__)


class MyProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_con_lost: asyncio.Future) -> None:
        self.on_con_lost = on_con_lost

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug("Connection opened")
        self.transport = transport

    def datagram_received(
            self, data: bytes, addr: Optional[Tuple[str, int]]
    ) -> None:
        logger.debug("Received: %s", data.decode())

    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.debug("Connection closed")
        self.on_con_lost.set_result(True)


async def create_udp_tls_socket(address: Tuple[str, int]) -> SSLSocket:
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    ssock = ssl.wrap_socket(sock)
    ssock.bind(address)

    return ssock


async def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    address = ("", 11111)
    sock = await create_udp_tls_socket(address)

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MyProtocol(on_con_lost=loop.create_future()),
        sock=sock,
    )

    # # Simulate the reception of data from the network.
    # loop.call_soon_threadsafe(transport.sendto, b"test-msg", address)

    try:
        await protocol.on_con_lost
    finally:
        transport.close()
        sock.close()


if __name__ == "__main__":
    asyncio.run(main())
