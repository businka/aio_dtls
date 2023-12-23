import asyncio
import logging
import socket
from asyncio import DatagramProtocol

from aio_dtls import DtlsSocket

logger = logging.getLogger('aio_dtls')
logging.basicConfig()
logger.setLevel(logging.DEBUG)


class EchoProtocol(DatagramProtocol):
    def __init__(self, server, endpoint, **kwargs):
        self.server = server
        self.transport = None
        self.endpoint = endpoint

    def connection_made(self, transport):
        print(f'udp connection_made')
        self.transport = transport

    def datagram_received(self, data, client_address):
        print(f'received from {client_address} {data}')

    def error_received(self, exc, address=None):
        print(f'protocol error received {exc}')

    def connection_lost(self, exc):
        print(f'Connection closed {exc}')

    def datagram_received_bad_message(self, message, client_address):
        print("receive_datagram - BAD REQUEST")


class Endpoint:
    def __init__(self):
        self.address = None
        self.raw_socket = None
        self.dtls_socket = None

    async def server_start(self, address=('127.0.0.1', 0)):
        self.address = address
        # family = socket.AF_INET
        self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dtls_socket = DtlsSocket(
            sock=self.raw_socket,
            endpoint=self,
        )
        self.dtls_socket.bind(address)
        await self.dtls_socket.listen(self.dtls_socket, EchoProtocol)
        if not self.address[1]:
            self.address = self.dtls_socket.address
        print(f'open socket {self.address[0]}:{self.address[1]}')

    async def send(self, data, address):
        self.dtls_socket.sendto(data, address)

    def raw_sendto(self, data, address):
        self.dtls_socket.raw_sendto(data, address)

    def close(self):
        if self.dtls_socket:
            self.dtls_socket.close()

    def __del__(self):
        self.close()


async def example():
    server_endpoint = Endpoint()
    await server_endpoint.server_start()
    client_endpoint = Endpoint()
    await client_endpoint.server_start()
    await client_endpoint.send(b'hello', server_endpoint.address)
    await asyncio.sleep(1)
    server_endpoint.close()
    client_endpoint.close()


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    loop.run_until_complete(example())
