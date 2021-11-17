class RecordLayer:
    def calc_pending_states(self, connection):
        """Create pending states for encryption and decryption."""
        keyLength, ivLength, createCipherFunc = \
            self._getCipherSettings(cipherSuite)

        macLength, digestmod = self._getMacSettings(cipherSuite)

        if not digestmod:
            createMACFunc = None
        else:
            createMACFunc = self._getHMACMethod(self.version)

        outputLength = (macLength * 2) + (keyLength * 2) + (ivLength * 2)

        # Calculate Keying Material from Master Secret
        keyBlock = calc_key(self.version, masterSecret, cipherSuite,
                            b"key expansion", client_random=clientRandom,
                            server_random=serverRandom,
                            output_length=outputLength)

        # Slice up Keying Material
        clientPendingState = ConnectionState()
        serverPendingState = ConnectionState()
        parser = Parser(keyBlock)
        clientMACBlock = parser.getFixBytes(macLength)
        serverMACBlock = parser.getFixBytes(macLength)
        clientKeyBlock = parser.getFixBytes(keyLength)
        serverKeyBlock = parser.getFixBytes(keyLength)
        clientIVBlock = parser.getFixBytes(ivLength)
        serverIVBlock = parser.getFixBytes(ivLength)

        if digestmod:
            # Legacy cipher
            clientPendingState.macContext = createMACFunc(
                compatHMAC(clientMACBlock), digestmod=digestmod)
            serverPendingState.macContext = createMACFunc(
                compatHMAC(serverMACBlock), digestmod=digestmod)
            if createCipherFunc is not None:
                clientPendingState.encContext = \
                    createCipherFunc(clientKeyBlock,
                                     clientIVBlock,
                                     implementations)
                serverPendingState.encContext = \
                    createCipherFunc(serverKeyBlock,
                                     serverIVBlock,
                                     implementations)
        else:
            # AEAD
            clientPendingState.macContext = None
            serverPendingState.macContext = None
            clientPendingState.encContext = createCipherFunc(clientKeyBlock,
                                                             implementations)
            serverPendingState.encContext = createCipherFunc(serverKeyBlock,
                                                             implementations)
            clientPendingState.fixedNonce = clientIVBlock
            serverPendingState.fixedNonce = serverIVBlock

        # Assign new connection states to pending states
        if self.client:
            clientPendingState.encryptThenMAC = \
                self._pendingWriteState.encryptThenMAC
            self._pendingWriteState = clientPendingState
            serverPendingState.encryptThenMAC = \
                self._pendingReadState.encryptThenMAC
            self._pendingReadState = serverPendingState
        else:
            serverPendingState.encryptThenMAC = \
                self._pendingWriteState.encryptThenMAC
            self._pendingWriteState = serverPendingState
            clientPendingState.encryptThenMAC = \
                self._pendingReadState.encryptThenMAC
            self._pendingReadState = clientPendingState

        if self.version >= (3, 2) and ivLength:
            # Choose fixedIVBlock for TLS 1.1 (this is encrypted with the CBC
            # residue to create the IV for each sent block)
            self.fixedIVBlock = getRandomBytes(ivLength)
