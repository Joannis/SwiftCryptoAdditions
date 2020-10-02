// See: https://signal.org/docs/specifications/doubleratchet/#introduction
// TODO: Header encryption

import Foundation
import CryptoKit

public protocol DoubleRatchetPrivateKey: Codable {
    associatedtype PublicKey: DoubleRatchetPublicKey
    
    init()
    
    var publicKey: PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKey: PublicKey) throws -> SharedSecret
}

public protocol DoubleRatchetPublicKey: Codable, Equatable {}

extension Curve25519.KeyAgreement.PrivateKey: DoubleRatchetPrivateKey {
    public func encode(to encoder: Encoder) throws {
        try rawRepresentation.encode(to: encoder)
    }
    
    public init(from decoder: Decoder) throws {
        try self.init(rawRepresentation: Data(from: decoder))
    }
}

extension Curve25519.KeyAgreement.PublicKey: DoubleRatchetPublicKey {
    public func encode(to encoder: Encoder) throws {
        try rawRepresentation.encode(to: encoder)
    }
    
    public init(from decoder: Decoder) throws {
        try self.init(rawRepresentation: Data(from: decoder))
    }
    
    public static func ==(lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

public protocol DoubleRatchetSymmetricEncryption {
    func encrypt<PlainText: DataProtocol, Nonce: DataProtocol>(_ data: PlainText, nonce: Nonce, usingKey: SymmetricKey) throws -> Data
    func decrypt<CipherText: DataProtocol, Nonce: DataProtocol>(_ data: CipherText, nonce: Nonce, usingKey: SymmetricKey) throws -> Data
}

struct NonceMismatch: Error {}

public struct DoubleRatchetAESGCMEncryption: DoubleRatchetSymmetricEncryption {
    public init() {}
    
    public func encrypt<PlainText, Nonce>(_ data: PlainText, nonce: Nonce, usingKey key: SymmetricKey) throws -> Data where PlainText : DataProtocol, Nonce : DataProtocol {
        try AES.GCM.seal(data, using: key).combined!
    }
    
    public func decrypt<CipherText, Nonce>(_ data: CipherText, nonce: Nonce, usingKey key: SymmetricKey) throws -> Data where CipherText : DataProtocol, Nonce : DataProtocol {
        // AES.GCM manages its own nonce, which is fine for Ratchet
        // The only reason nonce is passed from externally, is for when the SymmetricEncryption mechanism doesn't manage it itself
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        
        return try AES.GCM.open(sealedBox, using: key)
    }
}

public struct DoubleRatchetChaChaPolyEncryption: DoubleRatchetSymmetricEncryption {
    public init() {}
    
    public func encrypt<PlainText, Nonce>(_ data: PlainText, nonce: Nonce, usingKey key: SymmetricKey) throws -> Data where PlainText : DataProtocol, Nonce : DataProtocol {
        try ChaChaPoly.seal(data, using: key).combined
    }
    
    public func decrypt<CipherText, Nonce>(_ data: CipherText, nonce: Nonce, usingKey key: SymmetricKey) throws -> Data where CipherText : DataProtocol, Nonce : DataProtocol {
        // ChaChaPoly manages its own nonce, which is fine for Ratchet
        // The only reason nonce is passed from externally, is for when the SymmetricEncryption mechanism doesn't manage it itself
        let sealedBox = try ChaChaPoly.SealedBox(combined: data)
        
        return try ChaChaPoly.open(sealedBox, using: key)
    }
}

/// Encodes & decodes a ratchet header into a lossless format
/// Can be used with Codable
public protocol RatchetHeaderEncoder {
    func encodeRatchetHeader<PublicKey: DoubleRatchetPublicKey>(_ header: RatchetMessage<PublicKey>.Header) throws -> Data
    func decodeRatchetHeader<PublicKey: DoubleRatchetPublicKey>(from data: Data) throws -> RatchetMessage<PublicKey>.Header
    func concatenate(authenticatedData: Data, withHeader header: Data) -> Data
}

public protocol RatchetKDF {
    func calculateRootKey(diffieHellmanSecret: SharedSecret, rootKey: SymmetricKey) throws -> SymmetricKey
    func calculateChainKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey
    func calculateMessageKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey
}

public struct DefaultRatchetKDF<Hash: HashFunction>: RatchetKDF {
    fileprivate let messageKeyConstant: Data
    fileprivate let chainKeyConstant: Data
    fileprivate let sharedInfo: Data
    
    public init(
        messageKeyConstant: Data,
        chainKeyConstant: Data,
        sharedInfo: Data
    ) {
        self.messageKeyConstant = messageKeyConstant
        self.chainKeyConstant = chainKeyConstant
        self.sharedInfo = sharedInfo
    }
    
    public func calculateRootKey(diffieHellmanSecret: SharedSecret, rootKey: SymmetricKey) throws -> SymmetricKey {
        diffieHellmanSecret.hkdfDerivedSymmetricKey(
            using: Hash.self,
            salt: rootKey.withUnsafeBytes { buffer in
                Data(buffer: buffer.bindMemory(to: UInt8.self))
            },
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
    }
    
    public func calculateChainKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey {
        let chainKey = HMAC<Hash>.authenticationCode(for: chainKeyConstant, using: chainKey)
        return SymmetricKey(data: chainKey)
    }
    
    public func calculateMessageKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey {
        let messageKey = HMAC<Hash>.authenticationCode(for: messageKeyConstant, using: chainKey)
        return SymmetricKey(data: messageKey)
    }
}

public struct RatchetAssociatedDataGenerator {
    private enum Mode {
        case constant(Data)
    }
    
    private let mode: Mode
    
    public static func constant<Raw: DataProtocol>(_ data: Raw) -> RatchetAssociatedDataGenerator {
        .init(mode: .constant(Data(data)))
    }
    
    func generateAssociatedData() -> Data {
        switch mode {
        case .constant(let data):
            return data
        }
    }
}

public struct DoubleRatchetConfiguration<Hash: HashFunction> {
    fileprivate let info: Data
    let symmetricEncryption: DoubleRatchetSymmetricEncryption
    let kdf: RatchetKDF
    let headerEncoder: RatchetHeaderEncoder
    let headerAssociatedDataGenerator: RatchetAssociatedDataGenerator
    let maxSkippedMessageKeys: Int
    
    public init<Info: DataProtocol>(
        info: Info,
        symmetricEncryption: DoubleRatchetSymmetricEncryption,
        kdf: RatchetKDF,
        headerEncoder: RatchetHeaderEncoder,
        headerAssociatedDataGenerator: RatchetAssociatedDataGenerator,
        maxSkippedMessageKeys: Int
    ) {
        self.info = Data(info)
        self.symmetricEncryption = symmetricEncryption
        self.kdf = kdf
        self.headerEncoder = headerEncoder
        self.headerAssociatedDataGenerator = headerAssociatedDataGenerator
        self.maxSkippedMessageKeys = maxSkippedMessageKeys
    }
}

extension SymmetricKey: Codable {
    public func encode(to encoder: Encoder) throws {
        let data = self.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
        
        try data.encode(to: encoder)
    }
    
    public init(from decoder: Decoder) throws {
        let data = try Data(from: decoder)
        self.init(data: data)
    }
}

@dynamicMemberLookup
public struct DoubleRatchetEngine<Hash: HashFunction, PrivateKey: DoubleRatchetPrivateKey> {
    public struct SkippedKey: Codable {
        let publicKey: PrivateKey.PublicKey
        let messageIndex: Int
        let messageKey: SymmetricKey
    }
    
    public struct State: Codable {
        // `RK`
        public fileprivate(set) var rootKey: SymmetricKey
        
        // `DHs`
        public fileprivate(set) var localPrivateKey: PrivateKey
        
        // `DHr`
        public fileprivate(set) var remotePublicKey: PrivateKey.PublicKey?
        
        // `CKs`
        public fileprivate(set) var sendingKey: SymmetricKey?
        
        // `CKr`
        public fileprivate(set) var receivingKey: SymmetricKey?
        
        // `PN`
        public fileprivate(set) var previousMessages: Int
        
        // `Ns`
        public fileprivate(set) var sentMessages: Int
        
        // `Nr`
        public fileprivate(set) var receivedMessages: Int
        
        public fileprivate(set) var skippedKeys = [SkippedKey]()
        
        fileprivate init(
            secretKey: SymmetricKey,
            contactingRemote remote: PrivateKey.PublicKey,
            configuration: DoubleRatchetConfiguration<Hash>
        ) throws {
            guard secretKey.bitCount == 256 else {
                throw DoubleRatchetError.invalidRootKeySize
            }
            
            let localPrivateKey = PrivateKey()
            let rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: localPrivateKey.sharedSecretFromKeyAgreement(with: remote),
                rootKey: secretKey
            )
            
            self.localPrivateKey = localPrivateKey
            self.rootKey = rootKey
            self.remotePublicKey = remote
            self.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: rootKey)
            self.receivingKey = nil
            
            self.previousMessages = 0
            self.sentMessages = 0
            self.receivedMessages = 0
        }
        
        fileprivate init(
            secretKey: SymmetricKey,
            localPrivateKey: PrivateKey,
            configuration: DoubleRatchetConfiguration<Hash>
        ) throws {
            guard secretKey.bitCount == 256 else {
                throw DoubleRatchetError.invalidRootKeySize
            }
            
            self.rootKey = secretKey
            self.localPrivateKey = localPrivateKey
            self.remotePublicKey = nil
            self.sendingKey = nil
            self.receivingKey = nil
            
            self.previousMessages = 0
            self.sentMessages = 0
            self.receivedMessages = 0
        }
    }
    
    public private(set) var state: State
    public let configuration: DoubleRatchetConfiguration<Hash>
    
    public init(
        state: State,
        configuration: DoubleRatchetConfiguration<Hash>
    ) {
        self.state = state
        self.configuration = configuration
    }
    
    public private(set) subscript<T>(dynamicMember keyPath: WritableKeyPath<State, T>) -> T{
        get { state[keyPath: keyPath] }
        set { state[keyPath: keyPath] = newValue }
    }
    
    public static func initializeSender(
        secretKey: SymmetricKey,
        contactingRemote remote: PrivateKey.PublicKey,
        configuration: DoubleRatchetConfiguration<Hash>
    ) throws -> DoubleRatchetEngine<Hash, PrivateKey> {
        let state = try State(
            secretKey: secretKey,
            contactingRemote: remote,
            configuration: configuration
        )
        return DoubleRatchetEngine<Hash, PrivateKey>(state: state, configuration: configuration)
    }
    
    public static func initializeRecipient(
        secretKey: SymmetricKey,
        contactedBy remote: PrivateKey.PublicKey,
        localPrivateKey: PrivateKey,
        configuration: DoubleRatchetConfiguration<Hash>,
        initialMessage: RatchetMessage<PrivateKey.PublicKey>
    ) throws -> (DoubleRatchetEngine<Hash, PrivateKey>, Data) {
        let state = try State(secretKey: secretKey, localPrivateKey: localPrivateKey, configuration: configuration)
        var engine = DoubleRatchetEngine<Hash, PrivateKey>(state: state, configuration: configuration)
        let plaintext = try engine.ratchetDecrypt(initialMessage)
        return (engine, plaintext)
    }
    
    public mutating func ratchetEncrypt<PlainText: DataProtocol>(_ plaintext: PlainText) throws -> RatchetMessage<PrivateKey.PublicKey> {
        guard let sendingKey = self.sendingKey else {
            throw DoubleRatchetError.uninitializedRecipient
        }
        
        // state.CKs, mk = KDF_CK(state.CKs)
        let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: sendingKey)
        self.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: sendingKey)
        
        // header = HEADER(state.DHs, state.PN, state.Ns)
        let header = RatchetMessage.Header(
            senderPublicKey: self.localPrivateKey.publicKey,
            previousChainLength: self.previousMessages,
            messageNumber: self.sentMessages
        )
        let headerData = try configuration.headerEncoder.encodeRatchetHeader(header)
        let nonce = configuration.headerEncoder.concatenate(
            authenticatedData: configuration.headerAssociatedDataGenerator.generateAssociatedData(),
            withHeader: headerData
        )
        
        // state.Ns += 1
        self.sentMessages += 1
        
        // return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
        let ciphertext = try configuration.symmetricEncryption.encrypt(plaintext, nonce: nonce, usingKey: messageKey)
        return RatchetMessage(
            header: header,
            ciphertext: ciphertext
        )
    }
    
    public mutating func ratchetDecrypt(_ message: RatchetMessage<PrivateKey.PublicKey>) throws -> Data {
        func skipMessageKeys(until keyIndex: Int) throws {
            if self.receivedMessages + configuration.maxSkippedMessageKeys < keyIndex {
                throw DoubleRatchetError.tooManySkippedMessages
            }
            
            guard let receivingKey = self.receivingKey else {
                return
            }
            
            while self.receivedMessages < keyIndex {
                let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: receivingKey)
                self.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: receivingKey)
                // TODO: Throttle backlog, there cannot be too many keys
                self.skippedKeys.append(
                    SkippedKey(
                        publicKey: message.header.senderPublicKey,
                        messageIndex: message.header.messageNumber,
                        messageKey: messageKey
                    )
                )
                if self.skippedKeys.count > self.configuration.maxSkippedMessageKeys {
                    self.skippedKeys.removeFirst()
                }
                
                self.receivedMessages += 1
            }
        }
        
        func decodeUsingSkippedMessageKeys() throws -> Data? {
            for i in 0..<self.skippedKeys.count {
                let skippedKey = self.skippedKeys[i]
                
                if skippedKey.messageIndex == message.header.messageNumber && message.header.senderPublicKey == skippedKey.publicKey {
                    self.skippedKeys.remove(at: i)
                    
                    return try decryptMessage(message, usingKey: skippedKey.messageKey)
                }
            }
            
            return nil
        }
        
        func diffieHellmanRatchet() throws {
            self.previousMessages = self.sentMessages
            self.sentMessages = 0
            self.receivedMessages = 0
            self.remotePublicKey = message.header.senderPublicKey
            
            self.rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: self.localPrivateKey.sharedSecretFromKeyAgreement(with: message.header.senderPublicKey),
                rootKey: self.rootKey
            )
            self.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: self.rootKey)
            self.localPrivateKey = PrivateKey()
            
            self.rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: self.localPrivateKey.sharedSecretFromKeyAgreement(with: message.header.senderPublicKey),
                rootKey: self.rootKey
            )
            self.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: self.rootKey)
        }
        
        // 1. Try skipped message keys
        if let plaintext = try decodeUsingSkippedMessageKeys() {
            return plaintext
        }
        
        // 2. Check if the publicKey matches the current key
        if message.header.senderPublicKey != self.remotePublicKey {
            // It seems that the kye is out of date, so it should be replaced
            try skipMessageKeys(until: message.header.previousChainLength)
            try diffieHellmanRatchet()
        }
        
        // 3.a. On-mismatch, Skip ahead in message keys until max. Store all the inbetween message keys in a history
        try skipMessageKeys(until: message.header.messageNumber)
        
        guard let receivingKey = self.receivingKey else {
            preconditionFailure("Somehow, the DHRatchet wasn't executed although the receivingKey was `nil`")
        }
        
        let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: receivingKey)
        self.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: receivingKey)
        self.receivedMessages += 1
        
        return try decryptMessage(message, usingKey: messageKey)
    }
    
    private func decryptMessage(_ message: RatchetMessage<PrivateKey.PublicKey>, usingKey messageKey: SymmetricKey) throws -> Data {
        let headerData = try configuration.headerEncoder.encodeRatchetHeader(message.header)
        let nonce = configuration.headerEncoder.concatenate(
            authenticatedData: configuration.headerAssociatedDataGenerator.generateAssociatedData(),
            withHeader: headerData
        )
        
        return try configuration.symmetricEncryption.decrypt(
            message.ciphertext,
            nonce: nonce,
            usingKey: messageKey
        )
    }
}

public struct RatchetMessage<PublicKey: DoubleRatchetPublicKey>: Codable {
    public struct Header: Codable {
        // `dh_pair`
        let senderPublicKey: PublicKey
        
        // `pn`
        let previousChainLength: Int
        
        // `N`
        let messageNumber: Int
    }
    
    let header: Header
    let ciphertext: Data
}

enum DoubleRatchetError: Error {
    case invalidRootKeySize, uninitializedRecipient, tooManySkippedMessages
}
