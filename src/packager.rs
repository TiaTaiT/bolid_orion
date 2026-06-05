use heapless::Vec as HVec;
use crate::crc::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpackError {
    EmptyData,
    InvalidLength,
    CrcMismatch,
    PayloadTooLarge,
}

pub struct Package<const MAX_DATA: usize = 252> {
    pub protected: bool,
    pub address: u8,
    pub message_key: u8,
    pub data: HVec<u8, MAX_DATA>,
}

pub fn unpack<const MAX_DATA: usize>(
    raw_data: &[u8],
    direction: Direction,
    key_parameter: u8,
) -> Result<Package<MAX_DATA>, UnpackError> {
    if raw_data.is_empty() {
        return Err(UnpackError::EmptyData);
    }

    let expected_length = usize::from(raw_data[1]) + 1;
    if raw_data.len() != expected_length {
        return Err(UnpackError::InvalidLength);
    }

    if !is_crc_valid(raw_data) {
        return Err(UnpackError::CrcMismatch);
    }

    let protected = (raw_data[0] >> 7) & 1 == 1;
    let address = raw_data[0] & 0x7F;

    let (message_key, payload_start) = match direction {
        Direction::Request => {
            if raw_data.len() < 4 {
                return Err(UnpackError::InvalidLength);
            }
            let global_key = key_parameter;
            let msg_key = raw_data[2] ^ global_key;
            (msg_key, 3)
        }
        Direction::Response => {
            let msg_key = key_parameter;
            (msg_key, 2)
        }
    };

    let payload = &raw_data[payload_start..raw_data.len() - 1];
    let mut data = HVec::<u8, MAX_DATA>::new();
    data.extend_from_slice(payload).map_err(|_| UnpackError::PayloadTooLarge)?;

    if protected {
        for byte in data.iter_mut() {
            *byte ^= message_key;
        }
    }

    Ok(Package {
        protected,
        address,
        message_key,
        data,
    })
}

pub fn pack<const MAX_DATA: usize, const MAX_PACKET: usize>(
    package: &Package<MAX_DATA>,
    direction: Direction,
    global_key: u8,
) -> Result<HVec<u8, MAX_PACKET>, PackError> {
    let mut raw_data = HVec::<u8, MAX_PACKET>::new();

    let protected_bit = if package.protected { 1 } else { 0 } << 7;
    raw_data.push(protected_bit | (package.address & 0x7F)).map_err(|_| PackError::BufferTooSmall)?;

    let header_len = match direction {
        Direction::Request => 3,
        Direction::Response => 2,
    };
    let required_len = package.data.len() + header_len + 1;
    raw_data.push((required_len - 1) as u8).map_err(|_| PackError::BufferTooSmall)?;

    if direction == Direction::Request {
        let encrypted_key = global_key ^ package.message_key;
        raw_data.push(encrypted_key).map_err(|_| PackError::BufferTooSmall)?;
    }

    for &byte in package.data.iter() {
        let b = if package.protected { byte ^ package.message_key } else { byte };
        raw_data.push(b).map_err(|_| PackError::BufferTooSmall)?;
    }

    let crc_val = get_crc8(&raw_data);
    raw_data.push(crc_val).map_err(|_| PackError::BufferTooSmall)?;

    Ok(raw_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL_KEY: u8 = 0x12;

    #[test]
    fn test_unprotected_key_assignment_request() {
        // [ADDR][LEN][KEY_BYTE][PAYLOAD...][CRC8]
        let raw_data = [0x03, 0x06, 0x00, 0x11, 0xBA, 0xBA, 0x8D];
        
        // Specifying MAX_DATA = 16 for the heapless package
        let package: Package<16> = unpack(&raw_data, Direction::Request, GLOBAL_KEY)
            .expect("Unpack failed");

        assert!(!package.protected);
        assert_eq!(package.address, 0x03);
        assert_eq!(package.message_key, 0x12); // 0x00 ^ GLOBAL_KEY (0x12)
        assert_eq!(package.data.as_slice(), &[0x11, 0xBA, 0xBA]);
    }

    #[test]
    fn test_unprotected_acknowledgement_response() {
        // [ADDR][LEN][PAYLOAD...][CRC8] (no key byte in response)
        let raw_data = [0x03, 0x05, 0x12, 0xBA, 0xBA, 0x63];
        
        let package: Package<16> = unpack(&raw_data, Direction::Response, GLOBAL_KEY)
            .expect("Unpack failed");

        assert!(!package.protected);
        assert_eq!(package.address, 0x03);
        assert_eq!(package.data.as_slice(), &[0x12, 0xBA, 0xBA]);
    }

    #[test]
    fn test_protected_request_roundtrip() {
        // Payload: B1=0x57, B2=0x02, B3=0x00
        let mut data = HVec::<u8, 16>::new();
        data.extend_from_slice(&[0x57, 0x02, 0x00]).unwrap();

        let package = Package {
            protected: true,
            address: 0x03,
            message_key: 0xBA,
            data,
        };

        // Pack with MAX_DATA=16, MAX_PACKET=16
        let packed: HVec<u8, 16> = pack(&package, Direction::Request, GLOBAL_KEY)
            .expect("Pack failed");

        // Required packet structure check:
        // [ADDR | 0x80] [LEN - 1] [KEY ^ GLOBAL_KEY] [B1 ^ KEY] [B2 ^ KEY] [B3 ^ KEY] [CRC]
        assert_eq!(packed[0], 0x83); 
        assert_eq!(packed[1], 0x06); // Total 7 bytes -> len-1 = 6
        assert_eq!(packed[2], 0xBA ^ GLOBAL_KEY); // 0xBA ^ 0x12 = 0xA8
        assert_eq!(packed[3], 0x57 ^ 0xBA); // 0xED
        assert_eq!(packed[4], 0x02 ^ 0xBA); // 0xB8
        assert_eq!(packed[5], 0x00 ^ 0xBA); // 0xBA

        // Symmetrical Unpack check
        let unpacked: Package<16> = unpack(&packed, Direction::Request, GLOBAL_KEY)
            .expect("Unpack failed");

        assert!(unpacked.protected);
        assert_eq!(unpacked.address, 0x03);
        assert_eq!(unpacked.message_key, 0xBA);
        assert_eq!(unpacked.data.as_slice(), &[0x57, 0x02, 0x00]);
    }

    #[test]
    fn test_protected_response_roundtrip() {
        // Payload: [0x58, 0x02, 0x00]
        let mut data = HVec::<u8, 16>::new();
        data.extend_from_slice(&[0x58, 0x02, 0x00]).unwrap();

        let package = Package {
            protected: true,
            address: 0x03,
            message_key: 0xBA,
            data,
        };

        // Pack Response format (no key byte in output)
        let packed: HVec<u8, 16> = pack(&package, Direction::Response, GLOBAL_KEY)
            .expect("Pack failed");

        // Required packet structure check:
        // [ADDR | 0x80] [LEN - 1] [B1 ^ KEY] [B2 ^ KEY] [B3 ^ KEY] [CRC]
        assert_eq!(packed[0], 0x83);
        assert_eq!(packed[1], 0x05); // Total 6 bytes -> len-1 = 5
        assert_eq!(packed[2], 0x58 ^ 0xBA); // 0xE2 (starts immediately at index 2)

        // Symmetrical Unpack check (passing KEY=0xBA as the known message key parameter)
        let unpacked: Package<16> = unpack(&packed, Direction::Response, 0xBA)
            .expect("Unpack failed");

        assert!(unpacked.protected);
        assert_eq!(unpacked.address, 0x03);
        assert_eq!(unpacked.message_key, 0xBA);
        assert_eq!(unpacked.data.as_slice(), &[0x58, 0x02, 0x00]);
    }

    #[test]
    fn test_unpack_payload_too_large() {
        let raw_data = [0x03, 0x06, 0x00, 0x11, 0xBA, 0xBA, 0x8D];
        
        // Expect failure because raw_data payload (3 bytes) exceeds MAX_DATA (2 bytes)
        let result: Result<Package<2>, UnpackError> = unpack(&raw_data, Direction::Request, GLOBAL_KEY);
        assert_eq!(result.err(), Some(UnpackError::PayloadTooLarge));
    }

    #[test]
    fn test_pack_buffer_too_small() {
        let mut data = HVec::<u8, 8>::new();
        data.extend_from_slice(&[0x11, 0x22]).unwrap();

        let package = Package {
            protected: false,
            address: 0x03,
            message_key: 0x00,
            data,
        };

        // Required packet length for unprotected request = 1(addr) + 1(len) + 1(key) + 2(data) + 1(crc) = 6 bytes.
        // Specifying MAX_PACKET = 5 should fail.
        let result: Result<HVec<u8, 5>, PackError> = pack(&package, Direction::Request, GLOBAL_KEY);
        assert_eq!(result.err(), Some(PackError::BufferTooSmall));
    }

    #[test]
    fn test_unpack_invalid_crc() {
        let raw_data = [0x03, 0x06, 0x00, 0x11, 0xBA, 0xBA, 0xFF]; // Invalid CRC (0xFF instead of 0x8D)
        let result: Result<Package<16>, UnpackError> = unpack(&raw_data, Direction::Request, GLOBAL_KEY);
        assert_eq!(result.err(), Some(UnpackError::CrcMismatch));
    }

    #[test]
    fn test_unpack_invalid_length() {
        let raw_data = [0x03, 0x09, 0x00, 0x11, 0xBA, 0xBA, 0x8D]; // Length byte claims 10 bytes, actual is 7
        let result: Result<Package<16>, UnpackError> = unpack(&raw_data, Direction::Request, GLOBAL_KEY);
        assert_eq!(result.err(), Some(UnpackError::InvalidLength));
    }

    #[test]
    fn test_unpack_empty_data() {
        let result: Result<Package<16>, UnpackError> = unpack(&[], Direction::Request, GLOBAL_KEY);
        assert_eq!(result.err(), Some(UnpackError::EmptyData));
    }

    #[test]
    fn test_protected_pack() {
        let package = Package {
            protected: true,
            address: 0x02,
            message_key: 0x0E,
            data: heapless::Vec::<u8, 32>::try_from([0x0A, 0x04, 0x00].as_slice()).unwrap(),
        };
        let packed_data: heapless::Vec<u8, 32> = pack(&package, Direction::Response, GLOBAL_KEY).unwrap();
        let expected_packet = 
            heapless::Vec::<u8, 32>::try_from([0x82, 0x05, 0x04, 0x0A, 0x0E, 0xAF].as_slice()).unwrap();
        assert_eq!(packed_data, expected_packet);
    }

    #[test]
    fn test_unpack_valid_request_crypted_packet() {
        let raw_data = [0x82, 0x06, 0x1C, 0x19, 0x0E, 0x0D, 0xD7]; // Example packet with valid CRC
        let package: Package<32>  = unpack(&raw_data, Direction::Request, GLOBAL_KEY)
            .expect("Failed to unpack valid packet");
        let expected_packet = 
            heapless::Vec::<u8, 32>::try_from([0x17, 0x00, 0x03].as_slice()).unwrap();
        assert!(package.protected);
        assert_eq!(package.address, 0x02);
        assert_eq!(package.data, expected_packet);
    }

    #[test]
    fn test_unpack_valid_response_crypted_packet() {
        const PRIVATE_KEY: u8 = 0xEB;
        let raw_data = [0x82, 0x05, 0xEF, 0x20, 0xEB, 0x59]; // Example packet with valid CRC
        let package: Package<32>  = unpack(&raw_data, Direction::Response, PRIVATE_KEY)
            .expect("Failed to unpack valid packet");
        let expected_packet = 
            heapless::Vec::<u8, 32>::try_from([0x04, 0xCB, 0x00].as_slice()).unwrap();
        assert!(package.protected);
        assert_eq!(package.address, 0x02);
        assert_eq!(package.data, expected_packet);
    }
}