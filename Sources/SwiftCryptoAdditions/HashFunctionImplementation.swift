import Crypto

internal protocol HashFunctionImplementation: HashFunction where Digest: DigestImplementation {
    static var littleEndian: Bool { get }
    mutating func update(from pointer: UnsafePointer<UInt8>)
    var hashValue: [UInt8] { get }
    var processedBytes: UInt64 { get set }
    var unprocessedByteCount: Int { get set }
    var unprocessedBytes: [UInt8] { get set }
}

internal protocol DigestImplementation: Digest {
    init(bytes: [UInt8])
}

extension HashFunctionImplementation {
    public mutating func update(bufferPointer data: UnsafeRawBufferPointer) {
        var pointer = data.bindMemory(to: UInt8.self).baseAddress!
        var count = data.count
        
        if unprocessedByteCount > 0 {
            let previouslyUnprocessedBytesCount = self.unprocessedByteCount
            
            if unprocessedByteCount + count >= Self.blockByteCount {
                let newlyCopiedBytes = Self.blockByteCount - unprocessedByteCount
                unprocessedBytes.withUnsafeMutableBytes { buffer in
                    buffer.baseAddress!
                        .advanced(by: previouslyUnprocessedBytesCount)
                        .copyMemory(from: pointer, byteCount: newlyCopiedBytes)
                }
                update(from: unprocessedBytes)
                pointer += newlyCopiedBytes
                count -= newlyCopiedBytes
                self.unprocessedByteCount = 0
                self.processedBytes += UInt64(Self.blockByteCount)
                
                // Make sure no original data is left behind
                self.unprocessedBytes = [UInt8](repeating: 0, count: Self.blockByteCount)
            } else {
                self.unprocessedBytes.withUnsafeMutableBytes { buffer in
                    buffer.baseAddress!
                        .advanced(by: previouslyUnprocessedBytesCount)
                        .copyMemory(from: pointer, byteCount: count)
                }
                self.unprocessedByteCount += count
            }
        }
        
        while count >= Self.blockByteCount {
            update(from: pointer)
            count -= Self.blockByteCount
        }
        
        if count > 0 {
            unprocessedBytes.withUnsafeMutableBytes { buffer in
                buffer.copyBytes(from: UnsafeRawBufferPointer(start: pointer, count: count))
            }
        }
    }
    
    public func finalize() -> Digest {
        // Make sure this doesn't accept more than 63 bytes of padding. 64 bytes of padding
        // 64 padding would only occur if `unprocessedByteCount` == 0, which means there's nothing to be done
        let leadingZeroes = (Self.blockByteCount - unprocessedByteCount) % 64
        
        // + 1 bit (0x80 byte) & the trailing bitLength as UInt64
        var data = [UInt8](repeating: 0, count: leadingZeroes + 1 + 8)
        data.withUnsafeMutableBufferPointer { buffer in
            // Then, write the amount of bits in big endian
            let oneBitPointer = buffer.baseAddress!.advanced(by: leadingZeroes)
                
            oneBitPointer.pointee = 0x80
            oneBitPointer.advanced(by: 1).withMemoryRebound(to: UInt64.self, capacity: 1) { pointer in
                pointer.pointee = (processedBytes << 3).bigEndian
            }
        }
        
        var copy = self
        copy.update(data: data)
        return Digest(bytes: copy.hashValue)
    }
}
