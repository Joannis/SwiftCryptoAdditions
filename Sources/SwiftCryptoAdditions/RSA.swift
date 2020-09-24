import Foundation
import Crypto
import DiscretionalPrecision
/*
struct RSAPrivateKey { // mostly per PKCS#1
    // DER has a version first
    let modulus: DHHugeInteger          // n
    let publicExponent: DHHugeInteger   // e
    let privateExponent: DHHugeInteger  // d
    let prime1: DHHugeInteger           // p
    let prime2: DHHugeInteger           // q
    let exponent1: DHHugeInteger        // dp
    let exponent2: DHHugeInteger        // dQ
    let coefficient: DHHugeInteger      // q_inv
}
*/

extension SimpleDERParser {
    /// - Note: Structural errors indicate a failure to find or interpret the
    ///   data expected by the application, but _not_ a corruption of the DER
    ///   structures themselves or of the parser state. Therefore, a parser is
    ///   NOT invalidated when one of these errors is thrown.
    enum DERStructureError: Error {
    
        /// A "require" received a no-more-data indication instead of a value.
        case unexpectedEndOfData(whileSeeking: DERTag)
        
        /// A "require" received a value with the wrong encoding.
        /// - Note: This failure mode will, of necessity, be revised and
        ///   reconsidered when support for non-universal tags is implemented.
        case typeMismatch(expected: DERTag, found: DERValue)
        
        /// A SEQUENCE require specified an exact count of items expected at the
        /// top level of the sequence but a different count was retrieved.
        case sequenceCountMismatch(expected: Int, found: Int)
        
        /// `requireEOF()` did _not_ receive a no-more-data indication.
        case unexpectedDataAfterEnd(found: DERValue)
    
    }
    
    public mutating func requireSequence(containing count: Int? = nil) throws -> [DERValue] {
        guard let content = try self.nextValue(inliningSequences: true) else {
            throw DERStructureError.unexpectedEndOfData(whileSeeking: .SEQUENCE)
        }
        guard case .sequence(let items) = content else {
            throw DERStructureError.typeMismatch(expected: .SEQUENCE, found: content)
        }
        guard count == nil || items.count == count else {
            throw DERStructureError.sequenceCountMismatch(expected: count!, found: items.count)
        }
        return items
    }
    
    public mutating func requireEOF() throws {
        let shouldBeNothing = try self.nextValue(inliningSequences: false)
        guard shouldBeNothing == nil else {
            throw DERStructureError.unexpectedDataAfterEnd(found: shouldBeNothing!)
        }
    }
}


/*
struct RSARawPublicKey: Equatable, Hashable {
    let n: ArbitraryInt
    let e: ArbitraryInt
    enum PE: Error {
        case badTopSequence, badTopSeqDERLen, noSecondTag, noSecondSeqDerLen, noOIDTag, noOIDBytes, badOID,
             badNullTag, badBitstringTag, noBitstringLen, badBitstring, badWrapSeqTag, noWrapSeqLen, noNextTag,
             badIntTag, noIntLen, noIntBytes, noENextTag, noEIntLen, noEIntBytes, excessTrailing
    }
    
    init?<S>(withDERBytes bytes: S) where S: Sequence, S.Element == UInt8 { try? self.init(withDERBytesThrowing: bytes) }
    
    init<S>(withDERBytesThrowing bytes: S) throws where S: Sequence, S.Element == UInt8 {
        var iter = bytes.makeIterator()
        
        guard let topSequenceTag = iter.next(), topSequenceTag == 0x30 else { throw PE.badTopSequence } // 0x30 = constructed SEQUENCE
        guard let _ = Self.readDERLength(from: &iter) else { throw PE.badTopSeqDERLen }
        guard var secondTag = iter.next() else { throw PE.noSecondTag }
        if secondTag == 0x30 { // SEQUENCE again. Try parsing as PKCS#8 container
            guard let _ = Self.readDERLength(from: &iter) else { throw PE.noSecondSeqDerLen }
            // Parse rsaEncryption OID
            guard let oidTag = iter.next(), oidTag == 0x06 else { throw PE.noOIDTag } // 0x06 = primitive OBJECT IDENTIFIER
            guard let oidLen = Self.readDERLength(from: &iter), oidLen == 9 else { throw PE.noOIDBytes } // 9 bytes of OID
            guard let oid1 = iter.next(), oid1 == 0x2a, let oid2 = iter.next(), oid2 == 0x86,
                  let oid3 = iter.next(), oid3 == 0x48, let oid4 = iter.next(), oid4 == 0x86,
                  let oid5 = iter.next(), oid5 == 0xf7, let oid6 = iter.next(), oid6 == 0x0d,
                  let oid7 = iter.next(), oid7 == 0x01, let oid8 = iter.next(), oid8 == 0x01,
                  let oid9 = iter.next(), oid9 == 0x01 else { throw PE.badOID } // 1.2.840.113549.1.1.1 = rsaEncryption
            // Parse NULL tag (no additional params)
            guard let nullTag = iter.next(), nullTag == 0x05, let nullLen = Self.readDERLength(from: &iter), nullLen == 0 else { throw PE.badNullTag }
            // Parse bitstring tag (container for RSA pubkey sequence), incliuding octet alignmen byte
            guard let bitstringTag = iter.next(), bitstringTag == 0x03 else { throw PE.badBitstringTag }
            guard let _ = Self.readDERLength(from: &iter) else { throw PE.noBitstringLen }
            guard let bitstringUnused = iter.next(), bitstringUnused == 0 else { throw PE.badBitstring } // bitstring must be octet-aligned
            // Now need to parse the header SEQUENCE for the RSA pubkey - doesn't really belong in this part,
            // but since we can't back up when using an iterator over a Swift.Sequence, oh well.
            guard let wrappedSeqTag = iter.next(), wrappedSeqTag == 0x30 else { throw PE.badWrapSeqTag }
            guard let _ = Self.readDERLength(from: &iter) else { throw PE.noWrapSeqLen }
            // Grab the next tag...
            guard let nextTag = iter.next() else { throw PE.noNextTag }
            secondTag = nextTag
            // ... and fall through to reading a pubkey
        }
        guard secondTag == 0x02 else { throw PE.badIntTag } // 0x02 = primitive INTEGER
        guard let nLen = Self.readDERLength(from: &iter) else { throw PE.noIntLen } // length of d value
        var nBytes = [UInt8]()
        for _ in 0..<nLen {
            guard let nByte = iter.next() else { throw PE.noIntBytes }
            nBytes.append(nByte)
        }
        guard let nextTag = iter.next(), nextTag == 0x02 else { throw PE.noENextTag }
        guard let eLen = Self.readDERLength(from: &iter) else { throw PE.noEIntLen } // length of e value
        var eBytes = [UInt8]()
        for _ in 0..<eLen {
            guard let eByte = iter.next() else { throw PE.noEIntBytes }
            eBytes.append(eByte)
        }
        guard iter.next() == nil else { throw PE.excessTrailing } // don't accept trailing data
        
        var nAlmost = ArbitraryInt.zero
        nBytes.reversed().forEach { nAlmost = (nAlmost << 8) | ArbitraryInt($0) }
        var eAlmost = ArbitraryInt.zero
        eBytes.reversed().forEach { eAlmost = (eAlmost << 8) | ArbitraryInt($0) }
        
        self.n = nAlmost
        self.e = eAlmost
    }
    private static func readDERLength<I: IteratorProtocol>(from iter: inout I) -> Int? where I.Element == UInt8 {
        guard let lengthByte1 = iter.next() else { return nil }
        var totalLength = Int(lengthByte1 & 0x7f) // short encoding: 0-127 bytes, long encoding: 0-126 following bytes
        if lengthByte1 & 0x80 != 0 {
            guard totalLength < 8 else { return nil } // just don't bother supporting lengths that take more than 7 bytes to express
            totalLength = 0
            for _ in 0..<(lengthByte1 & 0x7f) {
                guard let nextByte = iter.next() else { return nil }
                totalLength = (totalLength << 8) | Int(nextByte) // length is encoded big endian so shift bytes in left
            }
        }
        return totalLength
    }
}
*/

extension Insecure {
    public enum RSA {
        public enum Signing {
            /// It has proven tremendously painful to track down any consistent source of truth regarding the PKCS#10 `SubjectPublicKeyInfo`
            /// structure; the IETF RFCs and ITU-T X.600-series specs cross-reference one another with considerable abandon, while the Internet
            /// at large has the unfortunate habit of further muddying the waters by incorrectly referring to the SPKI structure as being from
            /// PKCS#8, which it is not; an identical structure does appear in PKCS#8, but that format is only intended for private keys and can
            /// not represent public keys in isoltion. It is likely that someone was originally trying to describe the SPKI record as being able to
            /// exist independently of the larger PKCS#8 structure, a fine distinction that may have escaped the OpenSSH and OpenSSL engineers who
            /// embedded the incorrect lableing into their software. SPKI as an entirely independent entity is specified by PKCS#10 and only that
            /// format, which is also the specification for Certificate Signing Requests, used when requesting X.509 certificates. Inevitably, the
            /// distinction is now long beyond the notice of most, and certainly far, far beyond the caring of anyone who doesn't happen to be
            /// trying to find the correct official definition of the record. The ITU-T X.nnn specifications and indeed the entire RSA encryption
            /// algorithm were terrible historical accidents; we can only hope one day to witness them fading forever from all human knowledge.
            ///
            /// At least eight RFCs specify various pieces of the complete SPKI definition in ASN.1, including but not limited to:
            ///
            /// - RFCs 5958 & 5480 (Asymmetric Key Packages, Elliptic Curve Cryptography SPKI)
            /// - RFCs 5911 & 5912 (ASN.1 modules for X.509/PKIX, CMS, and S/MIME)
            /// - RFCs 3279 & 5280 (X.509 PKI Certificate and CRL Profile, and Algorithms related thereto)
            /// - RFCs 2986 & 5208 (PKCS#10 and PKCS#8v1.2)
            ///
            /// The PKCS#10 `SubjectPublicKeyInfo` definition, as suitably specialized for encapsulating a PKCS#1 `RSAPublicKey` record (also shown),
            /// appears below. The record has simply been manually specialized for RSA instead of using ASN.1's unusual generic parameterizaton
            /// facility, both for simplicity and to avoid any ambiguities of encoding.
            /// ````
            /// rsaEncryption OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 1 }
            ///
            /// RSAAlgorithmIdentifier ::= SEQUENCE {
            ///   algorithm  rsaEncryption,
            ///   parameters NULL
            /// }
            ///
            /// SubjectRSAPublicKeyInfo ::= SEQUENCE {
            ///   identifier       RSAAlgorithmIdentifier,
            ///   subjectPublicKey BIT STRING (CONTAINING RSAPublicKey)
            /// }
            ///
            /// RSAPublicKey ::= SEQUENCE {
            ///   modulus         INTEGER, -- n
            ///   publicExponent  INTEGER  -- e
            /// }
            /// ````
            public struct PublicKey: Equatable, Hashable {
                // Modulus n
                public let modulus: ArbitraryInt
                
                // PublicExponent e
                public let publicExponent: ArbitraryInt

                enum PubkeyParseError: Error {
                    case invalidInitialSequence, invalidAlgorithmIdentifier, invalidSubjectPubkey, forbiddenTrailingData, invalidRSAPubkey
                }
                
                public init(publicExponent: ArbitraryInt, modulus: ArbitraryInt) {
                    self.publicExponent = publicExponent
                    self.modulus = modulus
                }
                
                public init<S>(withDERBytes bytes: S) throws where S: Sequence, S.Element == UInt8 {
                    var parser = SimpleDERParser(parsing: bytes)
                    
                    // Parse body - in almost any ASN.1, first value is a sequence holding entire content.
                    var items = try parser.requireSequence(containing: 2)
                    try parser.requireEOF()
                    
                    // We might have a PKCS#1 RSA key already, but more likely it's a PKCS#8 SPKI. SPKI will have a SEQUENCE and a BIT STRING
                    // as its content, in which case we need to verify the algorithm id, extract the bit string, and do a fresh parse on that.
                    // We can then fall through to the PKCS#1 case from there and just like that both formats are supported.
                    if case .sequence(let algIdent) = items[0] {
                        // Content is the algorithm identifier (whose value is constant in our case), followed by the pubkey bitstring.
                        // The bit count must be to the nearest byte, which really begs the question, why not use OCTET STRING... even
                        // better, how about something saner than DER, like Malbolge or maybe IE6-compatible JavaScript...
                        guard algIdent == [.objectIdentifier(arcs: [1, 2, 840, 113549, 1, 1, 1]), .null] else {
                            throw PubkeyParseError.invalidAlgorithmIdentifier
                        }
                        guard case .bitString(let subjectPubkey, let bits) = items[1], bits & 0x07 == 0 else {
                            throw PubkeyParseError.invalidSubjectPubkey
                        }
                        parser = SimpleDERParser(parsing: subjectPubkey)
                        guard let pubkeyContent = try parser.nextValue(),
                              case .sequence(let pubkeyItems) = pubkeyContent, pubkeyItems.count == 2 else {
                            throw PubkeyParseError.invalidInitialSequence
                        }
                        items = pubkeyItems // resume previous flow
                    }
                    
                    guard case .integer(let n) = items[0], case .integer(let e) = items[1] else {
                        throw PubkeyParseError.invalidRSAPubkey
                    }
                    guard try parser.nextValue(inliningSequences: false) == nil else {
                        throw PubkeyParseError.forbiddenTrailingData
                    }
                    
                    // And we're done, the DER parser already turned the integers into arbitrary-precision values.
                    self.modulus = n
                    self.publicExponent = e
                }
                
                public func isValidSignature<D: DataProtocol>(_ signature: ArbitraryInt, for data: D) -> Bool {
                    let modulusOctets = modulus.byteWidth
                    let signatureOctets = signature.byteWidth
                    
                    if modulusOctets != signatureOctets {
                        return false
                    }
                    
                    // Part of RSAVP1
                    guard signature > .zero && signature < modulus - 1 else {
                        return false
                    }
                    
                    // Part of RSAVP1
                    // m = s^e mod n
                    let message = signature.montgomeryExponentiation(
                        exponent: publicExponent,
                        modulus: modulus
                    )
                    
                    return message == ArbitraryInt(data: data, sign: false)
                }
            }
            
            public struct PrivateKey {
                // Private Exponent d
                public let privateExponent: ArbitraryInt
                
                // Public Exponent e
                public let publicKey: PublicKey
                
                // Modulus n
                public let modulus: ArbitraryInt
                
                public init(privateExponent: ArbitraryInt, publicExponent: ArbitraryInt, modulus: ArbitraryInt) {
                    self.privateExponent = privateExponent
                    self.modulus = modulus
                    self.publicKey = PublicKey(publicExponent: publicExponent, modulus: modulus)
                }
                
                public init(bits: Int = 2047, modulus: ArbitraryInt = .diffieHellmanGroup14) {
                    self.privateExponent = ArbitraryInt.random(bits: bits)
                    self.modulus = modulus
                    let publicExponent = Generator.generator2.bignum.montgomeryExponentiation(
                        exponent: self.privateExponent,
                        modulus: modulus
                    )
                    self.publicKey = PublicKey(publicExponent: publicExponent, modulus: modulus)
                }
                
                public func formSecret(with publicKey: PublicKey) -> SharedSecret {
                    let secret = publicKey.publicExponent.montgomeryExponentiation(exponent: self.privateExponent, modulus: modulus)
                    return SharedSecret(bignum: secret)
                }
                
                public func signature<D: DataProtocol>(for message: D) throws -> ArbitraryInt {
                    let message = ArbitraryInt(data: message, sign: false)
                    
                    guard message > .zero && message < modulus - 1 else {
                        throw RSAError.messageRepresentativeOutOfRange
                    }
                    
                    return signature(for: message)
                }
                
                public func signature(for message: ArbitraryInt) -> ArbitraryInt {
                    return message.montgomeryExponentiation(exponent: privateExponent, modulus: modulus)
                }
                
                public func signPkcs1Padded(_ message: ArbitraryInt) throws -> ArbitraryInt {
                    let bytes = try PKCS1Padding.paddedBytes(
                        data: message.bytes(),
                        modulus: modulus
                    )
                    
                    guard bytes.count % 8 == 0 else {
                        fatalError("Result is not a multiple of 8 bytes")
                    }
                    
                    let message = ArbitraryInt(bytes: bytes, sign: false)
                    return message.montgomeryExponentiation(exponent: privateExponent, modulus: modulus)
                }
            }
            
            internal struct Generator {
                let bignum: ArbitraryInt
                
                internal static let generator2 = Generator(bignum: 2)
            }
            
            public struct SharedSecret {
                let bignum: ArbitraryInt
                
                public func asArbitraryInt() -> ArbitraryInt {
                    return bignum
                }
            }
        }
    }
}

// TODO: This should be properly formatted in the first place, instead of mapping this as a hack
let diffieHellmanGroup14Prime: [UInt] = ([
    0xFFFFFFFFFFFFFFFF, 0xC90FDAA22168C234, 0xC4C6628B80DC1CD1,
    0x29024E088A67CC74, 0x020BBEA63B139B22, 0x514A08798E3404DD,
    0xEF9519B3CD3A431B, 0x302B0A6DF25F1437, 0x4FE1356D6D51C245,
    0xE485B576625E7EC6, 0xF44C42E9A637ED6B, 0x0BFF5CB6F406B7ED,
    0xEE386BFB5A899FA5, 0xAE9F24117C4B1FE6, 0x49286651ECE45B3D,
    0xC2007CB8A163BF05, 0x98DA48361C55D39A, 0x69163FA8FD24CF5F,
    0x83655D23DCA3AD96, 0x1C62F356208552BB, 0x9ED529077096966D,
    0x670C354E4ABC9804, 0xF1746C08CA18217C, 0x32905E462E36CE3B,
    0xE39E772C180E8603, 0x9B2783A2EC07A28F, 0xB5C55DF06F4C52C9,
    0xDE2BCBF695581718, 0x3995497CEA956AE5, 0x15D2261898FA0510,
    0x15728E5A8AACAA68, 0xFFFFFFFFFFFFFFFF
] as [UInt]).map(\.bigEndian)

extension ArbitraryInt {
    /// See: https://tools.ietf.org/html/rfc3526#page-3
    public static let diffieHellmanGroup14 = ArbitraryInt(
        normalizing: diffieHellmanGroup14Prime,
        sign: false
    )
    
    public enum OverwrittenBits {
        case none, one, two
    }

    public static func random(bits: Int = 2047, topBits: OverwrittenBits = .one, bottomBits: OverwrittenBits = .none) -> ArbitraryInt {
        // Makes sure that 65 bits counts as 2 words, rather than 1
        let wordCount = (bits + 64 - 1) / 64
        let lastWordBits = (bits - 1) % 64
        
        // If all bits are set, a full mask is used, removing no bits
        // If bits are missing, the extra bits are removed
        let lastWordBitMask = lastWordBits == 64 ? UInt.max : (1 << (UInt(lastWordBits) + 1)) - 1
        
        let words = [UInt](unsafeUninitializedCapacity: wordCount) { (buffer, count) in
            var rng = SystemRandomNumberGenerator()
            
            if wordCount != 0 {
                for i in 0..<wordCount {
                    buffer[i] = rng.next()
                }
            }
            
            buffer[wordCount - 1] &= lastWordBitMask
            count = wordCount
        }
        
        return ArbitraryInt(normalizing: words, sign: false)
    }
    
    public init<D: DataProtocol>(data bytes: D, sign: Bool) {
        self.init(bytes: Array(bytes), sign: sign)
    }
}

public struct RSAError: Error {
    let message: String
    
    static let messageRepresentativeOutOfRange = RSAError(message: "message representative out of range")
}
