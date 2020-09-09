import Crypto

public struct SHA1Digest: DigestImplementation {
    internal let bytes: [UInt8]
    public static let byteCount = SHA1.byteCount
    
    internal init(bytes: [UInt8]) {
        self.bytes = bytes
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
}

public struct SHA1: HashFunctionImplementation {
    public typealias Digest = SHA1Digest
    
    internal static let littleEndian = false
    public static let blockByteCount = 64
    public static let byteCount = 20
    
    var h0: UInt32 = 0x67452301
    var h1: UInt32 = 0xEFCDAB89
    var h2: UInt32 = 0x98BADCFE
    var h3: UInt32 = 0x10325476
    var h4: UInt32 = 0xC3D2E1F0
    
    var a: UInt32 = 0
    var b: UInt32 = 0
    var c: UInt32 = 0
    var d: UInt32 = 0
    var e: UInt32 = 0
    
    var f: UInt32 = 0
    var k: UInt32 = 0
    var temp: UInt32 = 0
    
    var processedBytes: UInt64 = 0
    var unprocessedByteCount: Int = 0
    var unprocessedBytes = [UInt8](repeating: 0, count: Self.blockByteCount)
    
    private mutating func reset() {
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        processedBytes = 0
    }
    
    var hashValue: [UInt8] {
        var buffer = [UInt8]()
        buffer.reserveCapacity(20)
        
        func convert(_ int: UInt32) {
            let int = int.bigEndian
            
            buffer.append(UInt8(int & 0xff))
            buffer.append(UInt8((int >> 8) & 0xff))
            buffer.append(UInt8((int >> 16) & 0xff))
            buffer.append(UInt8((int >> 24) & 0xff))
        }
        
        convert(h0)
        convert(h1)
        convert(h2)
        convert(h3)
        convert(h4)
        
        return buffer
    }
    
    public init() {
        reset()
    }
    
    mutating func update(from pointer: UnsafePointer<UInt8>) {
        var w = pointer.withMemoryRebound(to: UInt32.self, capacity: 16, { pointer in
            return [
                pointer[0].bigEndian, pointer[1].bigEndian, pointer[2].bigEndian, pointer[3].bigEndian,
                pointer[4].bigEndian, pointer[5].bigEndian, pointer[6].bigEndian, pointer[7].bigEndian,
                pointer[8].bigEndian, pointer[9].bigEndian, pointer[10].bigEndian, pointer[11].bigEndian,
                pointer[12].bigEndian, pointer[13].bigEndian, pointer[14].bigEndian, pointer[15].bigEndian,
                ]
        })
        
        w.reserveCapacity(80)
        
        for i in 16...79 {
            w.append(leftRotate(w[i &- 3] ^ w[i &- 8] ^ w[i &- 14] ^ w[i &- 16], count: 1))
        }
        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        
        for i in 0...79 {
            switch i {
            case 0...19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            case 20...39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            case 40...59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            default:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            }
            
            temp = leftRotate(a, count: 5) &+ f &+ e &+ w[i] &+ k
            e = d
            d = c
            c = leftRotate(b, count: 30)
            b = a
            a = temp
        }
        
        h0 = h0 &+ a
        h1 = h1 &+ b
        h2 = h2 &+ c
        h3 = h3 &+ d
        h4 = h4 &+ e
    }
}

fileprivate func leftRotate(_ x: UInt32, count c: UInt32) -> UInt32 {
    return (x << c) | (x >> (32 - c))
}
