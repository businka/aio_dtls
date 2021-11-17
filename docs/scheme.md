* CoapServer
  * endpoints {coap|coaps.address}
    * CoapEndpoint
      * Socket
      * CoapProtocol
    * CoapsEndpoint
      * DtlsSocket
        * Socket
        * DtlsProtocol
        * ConnectionSessionManager 
        * Connection
      * CoapProtocol
  * resources {url}
    * Resource 