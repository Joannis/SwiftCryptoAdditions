import DiscretionalPrecision
import Foundation

public struct PKCS1PaddingError: Error {
    private let message: String
    
    static let messageTooLong = PKCS1PaddingError(message: "Message too long")
}

internal struct PKCS1Padding {
    internal static func paddedBytes<Data: DataProtocol>(data: Data, modulus: ArbitraryInt) throws -> [UInt8] {
        let mLen = data.count
        let k = ((modulus.bitWidth + 7) / 8)
        if mLen > k - 11 {
            throw PKCS1PaddingError.messageTooLong
        }
        
        let paddingSize = k - mLen - 3
        
        // 0x00 | 0x02 | PS | 0x00 | M
        let bufferSize = 2 + paddingSize + 1 + mLen
        return [UInt8](unsafeUninitializedCapacity: bufferSize) { buffer, count in
            buffer[0] = 0x00
            buffer[1] = 0x02
            
            for i in 2..<2+paddingSize {
                buffer[i] = .random(in: 1 ... .max)
            }
            
            buffer[2 + paddingSize] = 0x00
            
            data.copyBytes(
                to: UnsafeMutableBufferPointer<UInt8>(
                    start: buffer.baseAddress?.advanced(by: 2 + paddingSize + 1),
                    count: mLen
                )
            )
            
            // Populate PS as <paddingSize> nonzero octets
            count = bufferSize
        }
    }
}
