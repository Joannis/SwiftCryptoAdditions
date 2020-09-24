import DiscretionalPrecision

/// The first 36 DER tags. Cribbed from Wikipedia, NOT any official
/// reference. Tag 15 is reserved. Ordered more or less by category.
enum DERTag: UInt32, CaseIterable, Codable, Equatable, Hashable {
    // basic collection (SEQUENCE == SEQUENCE OF, SET == SET OF)
    case SEQUENCE = 16, SET = 17
    
    // fundamental numeric types
    case BOOLEAN = 1, INTEGER = 2, NULL = 5, REAL = 9

    // bitwise and bytewise binary streams
    case BITSTRING = 3, OCTETSTRING = 4

    // object identifiers
    case OBJECTIDENTIFIER = 6, RELATIVE_OID = 13, OID_IRI = 35, RELATIVE_OID_IRI = 36

    // a whole lotta kindsa strings
    case UTF8STRING = 12, NUMERICSTRING = 18, PRINTABLESTRING = 19, T61STRING = 20,
         VIDEOTEXSTRING = 21, IA5STRING = 22, GRAPHICSTRING = 25, VISIBLESTRING = 26,
         GENERALSTRING = 27, UNIVERSALSTRING = 28, CHARACTERSTRING = 29, BMPSTRING = 30

    // date and time
    case TIME = 14, UTCTIME = 23, GENERALIZEDTIME = 24, DATE = 31,
         TIME_OF_DAY = 32, DATE_TIME = 33, DURATION = 34

    // misc - enumerations, object descriptors, and external type embeddings
    case OBJECTDESCRIPTOR = 7, EXTERNAL = 8, ENUMERATED = 10, EMBEDDEDPDV = 11

}

/// A whole mess of different ways the DER parse can go wrong. For a canonical,
/// unambiguous data encoding, there sure are a lot of ways for DER to get
/// corrupted, mis-encoded, or maliciously messed with...
enum DERParseError: Error {
    // Things that go wrong reading the data type and metadata of a value
    // (EOD in middle of tag number, forbidden leading 0, too long to parse, tag has wrong encoding, unrecognized class 0 tag)
    case incompleteTagNumber, invalidTagNumberExtension, overlengthTagNumber, invalidConstructedEncoding, invalidUniversalTag
    
    // Things that go wrong reading the size of a value
    // (EOD with no length value, fobidden indefinite encoding, too long to parse, EOD in middle of length value)
    case missingTagLength, invalidIndefiniteLength, overlengthTagLength, incompleteLengthEncoding
    
    // Things that go wrong reading a value's raw data
    // (EOD in middle of tag data)
    case incompleteTagData
    
    // Things that go wrong decoding specific value types
    // (EOD during outlined sequence)
    case incorrectSequenceLength
    // (forbidden boolean encoding, forbidden leading integer, forbidden data with null, nonsensical real number value)
    case invalidBooleanEncoding, invalidIntegerEncoding, invalidNullEncoding, invalidRealEncoding
    // (bitstring trailing bit count out of range, final subidentifier octet marked as continuation, too big to parse)
    case invalidBitstringEncoding, invalidObjectIdentifierEncoding, overlengthObjectIdentifier
    
    // You tried to reuse a SimpleDERParser after it hit a parse error
    case parserNotInService
}

/// Friendlier "decoded" forms of the DER tags we know intrinsically how to
/// handle on our own.
public enum DERValue: Hashable {
    // Inlined collections with complete contents
    case sequence(contents: [DERValue]), set(contents: Set<DERValue>)
    
    // Outlined collection begin/end markers
    case sequenceBegin, sequenceEnd, setBegin, setEnd
    
    // Scalars (boolean, arbitrary-precision integer, NULL, up-to-double-precision binary decimal)
    case boolean(Bool), integer(ArbitraryInt), null, real(Double)
    
    // Binary data (string of individual bits, stream of whole bytes)
    case bitString([UInt8], bits: UInt), octetString([UInt8])
    
    // OID (each item in the array is a subidentifier)
    case objectIdentifier(arcs: [UInt64])
    
    // Anything we don't know how to parse
    case unknown(tag: UInt32, length: Int, content: [UInt8])
}

/// - Note: Because DER parsing can fail and `makeIterator()` can not signal
///   error conditions by throwing, nor by an unambiguous `nil` return, this
///   parser can not act as a `Sequence` unless used in "all-at-once" mode,
///   which may be highly inefficient for some ASN.1 structures.
///
/// - TODO: Specialize for sequences where Sequence.withContiguousStorageIfAvailable(_:) returns non-nil
/// - TODO: Specialize for Collections
/// - TODO: Improve the Sequence-ness by figuring out a way to return tags without entire buffers
public struct SimpleDERParser {
    private var byteOffset: Int
    private var base: AnyIterator<UInt8>
    
    public init<S>(parsing bytes: S) where S: Sequence, S.Element == UInt8 {
        self.byteOffset = 0
        self.base = AnyIterator(bytes.makeIterator())
    }
    
    /// Simple wrapper for the iterator to maintain our byte offset value.
    private mutating func nextByte() throws -> UInt8? {
        // Acts as a chokepoint, allowing invalidation of the entire parser by setting the current offset
        // negative. Everything that can be done with a parser goes through this method, guaranteeing no
        // further parsing attempts can be made once an error occurs (DER errors are not recoverable).
        guard byteOffset >= 0 else {
            throw DERParseError.parserNotInService
        }
        
        let result = self.base.next()
        
        if result != nil {
            self.byteOffset += 1
        }
        return result
    }
    
    /// Read up to 32 bits of potentially continuation-encoded tag number. DER
    /// spec places no limit on the encoded length of a tag number but for
    /// practicality we limit it to 28 bits (`7 * 4 < 31`, but `7 * 5` isn't).
    private mutating func readTagNumber(offset tagOffset: Int) throws -> UInt32? {
        guard let nextTag = try self.nextByte() else {
            return nil // End of data
        }
        
        let tagClass = nextTag >> 6, tagIsConstructed = nextTag & 0x20 != 0 ? true : false, baseTagNumber = nextTag & 0x1f
        var tagNumber = UInt32(baseTagNumber)
        
        if baseTagNumber == 0x1f { // multiple octet encoding of tag number
            var nextOctet = try invalidateIfMissing(self.nextByte(), guarding: .incompleteTagNumber)
            
            // BER forbids leading zero octets
            try invalidateUnless(nextOctet & 0x7f != 0, guarding: .invalidTagNumberExtension)
            
            tagNumber = UInt32(nextOctet & 0x7f)
            while nextOctet & 0x80 != 0 {
                // Reject tag numbers longer than 28 bits for simplicity of implementation
                try invalidateUnless(self.byteOffset - tagOffset < 4, guarding: .overlengthTagNumber)
                
                nextOctet = try invalidateIfMissing(self.nextByte(), guarding: .incompleteTagNumber)
                tagNumber = (tagNumber << 7) | UInt32(nextOctet & 0x7f)
            }
        }
        
        // For universal tags, validate what we can.
        if tagClass == 0x0 {
            // Universal class means it has to be one of the ones we recognize
            let knownTag = try invalidateIfMissing(DERTag(rawValue: tagNumber), guarding: .invalidUniversalTag)
            
            // Of the defined universal tags, only embeddings and collections can be encoded as constructed in DER. Those in turn MUST be so encoded.
            try invalidateUnless(tagIsConstructed == Set([.EXTERNAL, .EMBEDDEDPDV, .SEQUENCE, .SET]).contains(knownTag), guarding: .invalidConstructedEncoding)
        }
        
        return tagNumber
    }
    
    /// Read up to 32 bits of potentially continuation encoded tag length. DER
    /// specifies up to 127 octets of tag length, but 4GB is more than enough to
    /// cover any practical usage this implementation is considered competent to
    /// support. Excess values are handled gracefully.
    private mutating func readTagLength(offset tagOffset: Int) throws -> UInt32 {
        let baseLengthOctet = try invalidateIfMissing(self.nextByte(), guarding: .missingTagLength)
        
        if baseLengthOctet & 0x80 == 0 {
            return UInt32(baseLengthOctet)
        }
        
        // DER forbids the indefinite-length encoding
        try invalidateUnless(baseLengthOctet != 0x80 && baseLengthOctet != 0xff, guarding: .invalidIndefiniteLength)
        // Reject lengths greater than 4GB
        try invalidateUnless(baseLengthOctet & 0x7f <= 4, guarding: .overlengthTagLength)
        
        var tagLength = UInt32(0)

        for _ in 0 ..< (baseLengthOctet & 0x7f) {
            let nextOctet = try invalidateIfMissing(self.nextByte(), guarding: .incompleteLengthEncoding)
            tagLength = (tagLength << 8) | UInt32(nextOctet)
        }
        return tagLength
    }
    
    /// Return next raw DER value as tag, length, bytes. Special-cased for the
    /// SEQUENCE, SEQUENCE OF, SET, and SET OF types - content is always empty
    /// for these. Caller is responsible for tracking whether the next raw value
    /// is still part of a sequence or set, as well as for dealing with nesting,
    /// when using this interface. Also returns offset of value starting from
    /// the first tag byte.
    mutating func nextRaw() throws -> (tag: UInt32, length: Int, content: [UInt8], offset: Int)? {
        let tagOffset = self.byteOffset
        
        // Get tag
        guard let tagNumber = try readTagNumber(offset: tagOffset) else {
            return nil
        }
        
        // Read length
        let tagLength = try readTagLength(offset: tagOffset)
        
        // Don't grab data for the collection types.
        if tagNumber == DERTag.SEQUENCE.rawValue || tagNumber == DERTag.SET.rawValue {
            return (tag: tagNumber, length: Int(tagLength), content: [], offset: tagOffset)
        }
        
        // Just loop over it byte by byte
        // TODO: Leverage withContiguousStorageIfAvailable() for a speed boost.
        let tagData = try [UInt8].init(unsafeUninitializedCapacity: Int(tagLength)) { buf, outCount in
            while outCount < buf.count {
                buf[outCount] = try invalidateIfMissing(self.nextByte(), guarding: .incompleteTagData)
                outCount += 1
            }
        }
        return (tag: tagNumber, length: Int(tagLength), content: tagData, offset: tagOffset)
    }
    
    private mutating func parseBoolean(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        // DER requires either 0 or 0xff as the encoding of BOOLEAN
        try invalidateUnless(raw.content.count == 1 && (raw.content[0] == 0 || raw.content[0] == 0xff), guarding: .invalidBooleanEncoding)
        return .boolean(raw.content[0] == 0xff ? true : false)
    }
    
    private mutating func parseInteger(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        try invalidateUnless(raw.length > 0, guarding: .invalidIntegerEncoding)
        
        // Integer must be all one octet, or the first NINE bits may not be 0x00 or 0xff1
        if raw.length > 1 {
            let nineBits = (UInt16(raw.content[0]) << 1) | UInt16(raw.content[1] >> 7)
            try invalidateUnless(nineBits != 0 && nineBits != 0x1ff, guarding: .invalidIntegerEncoding)
        }
        
        // Convert from 2's complement to sign-magnitude for ArbitraryInt's benefit.
        // Something's not quite right about needing to do this, but worry about that later.
        let isNegative = raw.content[0] >> 7 != 0
        var value = raw.content.reversed().reduce(ArbitraryInt.zero) { ($0 << 8) | (isNegative ? ~$1 : $1) }

        if isNegative {
            value = -(value + 1)
        }
        return .integer(value)
    }
    
    private mutating func parseNull(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        try invalidateUnless(raw.length == 0, guarding: .invalidNullEncoding)
        return .null
    }

    private mutating func parseReal(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        // TODO
        /*
        - If the real value is the value plus zero, there shall be no contents octets in the encoding.
        - When bits 8-7 = 01, there shall be only one contents octet, with values as follows:
            01000000 +inf
            01000001 -inf
            01000010 NaN
            01000011 -0
        - Bit 8 of the first contents octet shall be set to 1.
        - If the mantissa M is non-zero, it shall be represented by a sign S, a positive integer value N and a binary scaling factor F such that:
            M = S ⨯ N, S = +1 or –1
        - Bit 7 of the first contents octets shall be 1 if S is –1 and 0 otherwise.
        - Bits 6 to 5 of the first contents octets shall be 00 (base 2)
        - Bits 4 to 3 of the first contents octet shall encode the value of the binary scaling factor F as an unsigned binary integer.
        - Bits 2 to 1 of the first contents octet shall encode the format of the exponent as follows:
            a) if bits 2-1 = 00, then the second contents octet encodes the value of the exponent as a 2's complement binary number
            b) if bits 2-1 = 01, then the second and third contents octets encode the value of the exponent as a 2's complement binary number
            c) if bits 2-1 = 10, then the second, third and fourth contents octets encode the value of the exponent as a 2's complement binary number
            d) if bits 2-1 = 11, then the second contents octet encodes the number of octets X used to encode the value of the exponent, and the third up to the (X plus 3)th (inclusive) contents octets encode the value of the exponent as a 2's complement binary number; the value of X shall be at least one; the first nine bits of the transmitted exponent shall not be all zeros or all ones.
        - The remaining contents octets encode the value of the integer N as an unsigned binary number.
        - Before encoding, the mantissa M and exponent E are chosen so that M is either 0 or is odd.
        - In encoding the value, the binary scaling factor F shall be zero.
        */
        return .unknown(tag: raw.tag, length: raw.length, content: raw.content)
    }
    
    private mutating func parseBitstring(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        try invalidateUnless(raw.length > 0, guarding: .invalidBitstringEncoding)
        if raw.length == 1 {
            // Length 1 requires an initial octet of 0 (a bitstring with no 1 bits)
            try invalidateUnless(raw.content[0] == 0, guarding: .invalidBitstringEncoding)
            return .bitString([0], bits: 0)
        } else {
            // "Unused trailing bits" value must be in range 0-7, and DER requires the unused bits to be zero
            try invalidateUnless(raw.content[0] < 8, guarding: .invalidBitstringEncoding)
            try invalidateUnless(raw.content.last!.trailingZeroBitCount >= raw.content[0], guarding: .invalidBitstringEncoding)

            return .bitString(Array(raw.content.dropFirst()), bits: UInt(((raw.length - 1) << 3) - Int(raw.content[0])))
        }
    }
    
    private mutating func parseOID(_ raw: (tag: UInt32, length: Int, content: [UInt8], offset: Int)) throws -> DERValue {
        // OIDs have no innate limits on either 1) the number of subidentifiers in the OID or, 2) the width
        // of the integer value of each subidentifier. In other words, you can have a theoretically limitless
        // number of ArbitraryInt-sized (i.e. any-sized!) subidentifiers in an OID.
        //
        // This is obviously patently absurd in any practical sense. Indeed, it fits well with the refusal of the
        // standard to place limits on the length of tag number encoding, or any reasonable limit on the size of
        // a tag's data. A limit _is_ placed on the latter, certainly: up to 127 octets of length, representing
        // an upper size limit of 2**1016, or roughly 10**306, a value that not only could not be represented
        // using every single bit of information in the entire Universe, but exceeds that limit by several
        // hundred orders of magnitude. As a span of time it exceeds the maximum estimated number of years for
        // protons to decay the _slow_ way, and indeed is a more than respectable percentage of the time estimated
        // for all matter in the universe to turn to liquid via quantum tunneling and fuse itself into primordial
        // iron even if protons _don't_ decay. In short, even the value that *does* have a limit has one whose
        // pointlessness soars far past the point of ridiculousity and enters the plaid zone of sheer ludicrosity.
        // (Light speed was too slow, you see.)
        //
        // All of this is to say that we will be placing our own limits on OID representation. It is remarked that
        // Windows will not handle OIDs whose *total* representation requires more than 64 bits. This code will be
        // more tolerant; it will handle up to 64 bits per subidentifier and up to 64 subidentifiers, for a total
        // potential usage of 512 bytes. I hope sincerely that humanity, by the time it could need that many OIDs,
        // has lost them, and indeed the concept of them, in so distant a forgotten past that it would require
        // infinities of endlessly expanding and dying universes to even hint upon the possibility of their recall.
        //
        // tl;dr of the tl;dr: OIDs are poorly specified and this author is displeased by it.
        //
        // P.S.: The limit on specifying a tag's data length is only valid in DER. In BER or CER encodings of ASN.1,
        //       the indefinite encoding allows for the same funny little truth found in good old C strings:
        //       No. Limit. At. All.
        try invalidateUnless(raw.length > 0, guarding: .invalidObjectIdentifierEncoding)
        
        var subids: [UInt64] = [], n = 0
        
        while n < raw.content.count {
            let pieces = raw.content.dropFirst(n).prefix(while: { $0 & 0x80 != 0 }).lazy.map { $0 & 0x7f }
            n += pieces.count
            try invalidateUnless(n < raw.content.count && (pieces.isEmpty || pieces.first != 0x80), guarding: .invalidObjectIdentifierEncoding)
            try invalidateUnless(pieces.count + 1 <= 9 /* UInt64.bitWidth / 7 */, guarding: .overlengthObjectIdentifier)
            let value = pieces.reduce(UInt64(0), { ($0 << 7) | (UInt64($1) << 7) }) | UInt64(raw.content[n])
            n += 1
            
            if subids.isEmpty {
                subids = [value / 40, value % 40]
            } else {
                subids.append(value)
                try invalidateUnless(subids.count < 64, guarding: .overlengthObjectIdentifier)
            }
        }
        return .objectIdentifier(arcs: subids)
    }

    private var outliningStack: [(stopOffset: Int, endToken: DERValue)] = []
    
    /// - Note: The fetch param should REALLY be an autoclosure, but doing it
    ///   that way resulted in the compiler pulling the "exclusive access to
    ///   self" bit out of its big trap, so oh well.
    private mutating func invalidateIfMissing<R>(_ fetch: R?, guarding error: DERParseError) throws -> R {
        guard let result = fetch else {
            self.byteOffset = -1
            throw error
        }
        return result
    }
    
    /// This condition param should also be an autoclosure. Again, compiler
    /// decided no autoclosure for you.
    private mutating func invalidateUnless(_ condition: Bool, guarding error: DERParseError) throws {
        guard condition else {
            self.byteOffset = -1 // invalidate self, all further actions will throw
            throw error
        }
    }
    
    /// Return next DER value as well-formed data representation, to the extent
    /// possible based on this implementation's knowledge of DER primitive
    /// types. A value with a tag that lacks a well-formed representation will
    /// be returned in the raw form (see `nextRaw()`). The caller may choose
    /// whether sequences and sets are returned with their contents inlined (the
    /// default), or represented as distinct sequence/set begin and end values
    /// with their contents returned in order by each call. This method will
    /// handle nesting correctly regardless of which mode is chosen (including
    /// the case of an "outlined" top-level sequence and an inlined nested
    /// sequence). While using outlined sequence mode, callers MUST NOT invoke
    /// the `nextRaw()` method or they will receive unpredictable results, and
    /// probably errors. (However, the parser is guaranteed not to trigger a
    /// fatal error or other terminal condition.)
    ///
    /// - Note: If an end-of-data condition is encountered during an outlined
    ///   sequence or set, it is treated as an error condition, but values in
    ///   the collection leading up to that condition may have already been
    ///   returned. The caller is responsible for detecting and handling this
    ///   edge case if so desired.
    public mutating func nextValue(inliningSequences inlineSequences: Bool = true) throws -> DERValue? {
        if let currentOutline = outliningStack.last {
            try invalidateUnless(self.byteOffset <= currentOutline.stopOffset, guarding: .incorrectSequenceLength)

            if self.byteOffset == currentOutline.stopOffset {
                defer { outliningStack.removeLast() }
                return currentOutline.endToken
            }
        }
        
        guard let raw = try self.nextRaw() else {
            // Make sure no entries are left on the outlining stack, otherwise there's an unbalanced outlined sequence
            try invalidateUnless(outliningStack.isEmpty, guarding: .incorrectSequenceLength)
            return nil
        }
        let tag = DERTag(rawValue: raw.tag)
        
        switch tag {
            // Parse the scalars we know
            case .BOOLEAN: return try parseBoolean(raw)
            case .INTEGER: return try parseInteger(raw)
            case .NULL: return try parseNull(raw)
            case .REAL: return try parseReal(raw)
            case .BITSTRING: return try parseBitstring(raw)
            case .OCTETSTRING: return .octetString(raw.content) // Nothing to decode, it's just bytes
            case .OBJECTIDENTIFIER: return try parseOID(raw)
            
            // Deal with sequences
            case .SEQUENCE, .SET:
                let stopOffset = self.byteOffset + raw.length

                guard inlineSequences else {
                    outliningStack.append((stopOffset: stopOffset, endToken: tag == .SEQUENCE ? .sequenceEnd : .setEnd))
                    return tag == .SEQUENCE ? .sequenceBegin : .setBegin
                }
                
                var values: [DERValue] = []
                while self.byteOffset < stopOffset {
                    // EOD here means the sequence length is wrong
                    values.append(try invalidateIfMissing(self.nextValue(inliningSequences: true), guarding: .incorrectSequenceLength))
                }
                // Stopped past the end of the sequence!
                try invalidateUnless(self.byteOffset == stopOffset, guarding: .incorrectSequenceLength)
                
                return tag == .SEQUENCE ? .sequence(contents: values) : .set(contents: Set(values))
            
            // Everything else just gets dumped into "unknown"
            default:
                return .unknown(tag: raw.tag, length: raw.length, content: raw.content)
        }
    }
}
