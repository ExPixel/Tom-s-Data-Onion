use std::io::{BufRead, Write};

fn onion_layer_0(input: &[u8], output: &mut Vec<u8>) {
    output.extend(input);
}

fn onion_layer_1(input: &[u8], output: &mut Vec<u8>) {
    output.extend(input.iter().map(|&b| (b ^ 0b01010101).rotate_right(1)));
}

fn onion_layer_2(input: &[u8], output: &mut Vec<u8>) {
    let mut bits = 0u32;
    let mut bits_count = 0;

    input.iter().for_each(|&byte| {
        if (byte >> 1).count_ones() % 2 == (byte & 1) as u32 {
            bits <<= 7;
            bits |= byte as u32 >> 1;
            bits_count += 7;

            if bits_count >= 8 {
                output.push((bits >> (bits_count - 8)) as u8);
                bits_count -= 8;
            }
        }
    });

    while bits_count >= 8 {
        output.push((bits >> (bits_count - 8)) as u8);
        bits_count -= 8;
    }
}

fn onion_layer_3(input: &[u8], output: &mut Vec<u8>) {
    // Updated with decrypted pieces as necessary. [DONE]
    const EXPECT_PRELUDE: &'static [u8] = b"==[ Layer 4/5: Network Traffic ]";

    let mut key = [0u8; 32];

    // We're going to reverse the key using 32 consecutive '=' signs and hope we get lucky and hit
    // the payload line. Then use the key to try and decrypt the header and see if what we get back is
    // the prelude. This is kind of a cheesy way of doing this.
    for pwindow in input.windows(32) {
        assert!(pwindow.len() == 32);

        key.iter_mut()
            .enumerate()
            .for_each(|(idx, k)| *k = pwindow[idx] ^ b'=');

        if input
            .iter()
            .take(EXPECT_PRELUDE.len())
            .zip(key.iter())
            .map(|(o, k)| *o ^ *k)
            .eq(EXPECT_PRELUDE.iter().copied())
        {
            // We have found the key :o
            break;
        }
    }

    output.extend(
        input
            .iter()
            .enumerate()
            .map(|(idx, &b)| b ^ (key[idx % 32])),
    );
}

fn onion_layer_4(input: &[u8], output: &mut Vec<u8>) {
    use std::net::Ipv4Addr;

    let expected_src = "10.1.1.10".parse::<Ipv4Addr>().unwrap();
    let expected_dst = "10.1.1.200".parse::<Ipv4Addr>().unwrap();

    let mut idx = 0;
    while idx < input.len() {
        let packet = match udp::read_packet(&input[idx..]) {
            Ok(packet) => packet,
            Err(packet_size) => {
                idx += packet_size;
                continue;
            }
        };
        idx += packet.len;

        if *packet.src.ip() != expected_src
            || *packet.dst.ip() != expected_dst
            || packet.dst.port() != 42069
        {
            continue;
        }

        output.extend(packet.data);
    }
}

fn onion_layer_5(input: &[u8], output: &mut Vec<u8>) {
    use aes::Aes256;
    use block_modes::block_padding::NoPadding;
    use block_modes::{BlockMode, Cbc};

    // unwrap key
    let kek = &input[0..32];
    let iv = &input[32..40];
    let encrypted_key = &input[40..80];
    let mut key = [0u8; 32];
    aes_ext::unwrap_key256(kek, iv, encrypted_key, &mut key);

    // decrypt payload
    let iv = &input[80..96];

    // resize output to a multiple of 16 bytes:
    let encrypted_payload_len = input.len() - 96;
    output.extend(&input[96..]); // encrypted payload
    output.resize_with(
        encrypted_payload_len + (16 - encrypted_payload_len % 16),
        || 0,
    );

    let cipher = Cbc::<Aes256, NoPadding>::new_var(&key, iv).unwrap();
    let out_len = {
        cipher
            .decrypt(output as &mut [u8])
            .expect("decrypt payload")
            .len()
    };
    output.truncate(out_len);
}

fn from_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    for idx in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[idx..(idx + 2)], 16).expect("bad hex"));
    }
    out
}

fn to_hex(data: &[u8]) -> String {
    const HEX: &'static [u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);
    for idx in 0..data.len() {
        out.push(HEX[(data[idx] >> 4) as usize] as char);
        out.push(HEX[(data[idx] & 0xF) as usize] as char);
    }
    out
}

fn main() {
    let unwrappers: &[fn(&[u8], &mut Vec<u8>)] = &[
        onion_layer_0,
        onion_layer_1,
        onion_layer_2,
        onion_layer_3,
        onion_layer_4,
        onion_layer_5,
    ];

    let mut buf_in = Vec::new();
    let mut buf_out = Vec::new();

    for (idx, f) in unwrappers.iter().enumerate() {
        unwrap_onion_layer(idx, &mut buf_in, &mut buf_out, f);
    }
}

fn unwrap_onion_layer<F>(
    layer_index: usize,
    input: &mut Vec<u8>,
    output: &mut Vec<u8>,
    unwrap_func: F,
) where
    F: FnOnce(&[u8], &mut Vec<u8>),
{
    let onion_file =
        std::fs::File::open(format!("onion{}.txt", layer_index)).expect("onion.txt not found");
    let mut onion_read = std::io::BufReader::new(onion_file);
    scan_to_payload(&mut onion_read, input);

    input.clear();
    while onion_read
        .read_until(b'\n', input)
        .expect("failed to read file")
        != 0
    {
        let new_len = input
            .iter()
            .enumerate()
            .rev()
            .find(|&(_, ch)| !ch.is_ascii_whitespace())
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        input.truncate(new_len);
    }

    output.clear();
    unwrap_func(ascii85::decode_in_place(input as &mut [u8]), output);

    let mut onion_file = std::fs::File::create(format!("onion{}.txt", layer_index + 1))
        .expect("onion.txt not found");
    onion_file.write_all(output).expect("write output");

    println!(
        "unwrapped onion{}.txt -> onion{}.txt",
        layer_index,
        layer_index + 1
    );
}

fn scan_to_payload<R: BufRead>(r: &mut R, buffer: &mut Vec<u8>) {
    const PAYLOAD_INDICATOR: &[u8] = b"==[ Payload ]==";

    buffer.clear();
    while r.read_until(b'\n', buffer).expect("failed to read file") != 0 {
        if buffer.starts_with(PAYLOAD_INDICATOR) {
            assert!(r.read_until(b'\n', buffer).expect("failed to read") != 0);
            buffer.clear();
            return;
        } else {
            buffer.clear();
        }
    }
    unreachable!("no payload indicator");
}

mod ascii85 {
    pub fn decode_in_place(mut input: &mut [u8]) -> &[u8] {
        if input.starts_with(b"<~") {
            input = &mut input[2..];
        }

        if input.ends_with(b"~>") {
            let len = input.len();
            input = &mut input[0..(len - 2)];
        }

        let mut write_idx = 0;
        let mut idx = 0;
        while idx < input.len() {
            if input[idx] == b'z' {
                input[write_idx] = 0;
                write_idx += 1;
                idx += 1;
                continue;
            }

            let chunk = (input.get(idx).copied().unwrap_or(b'u') as u32 - 33) * (85u32.pow(4))
                + (input.get(idx + 1).copied().unwrap_or(b'u') as u32 - 33) * (85u32.pow(3))
                + (input.get(idx + 2).copied().unwrap_or(b'u') as u32 - 33) * (85u32.pow(2))
                + (input.get(idx + 3).copied().unwrap_or(b'u') as u32 - 33) * (85u32.pow(1))
                + (input.get(idx + 4).copied().unwrap_or(b'u') as u32 - 33) * (85u32.pow(0));

            // The number of valid bytes that aren't padding.
            let valid = std::cmp::min(4, input.len() - idx - 1);

            for c in 0..valid {
                input[write_idx] = (chunk >> (24 - c * 8)) as u8;
                write_idx += 1;
            }

            idx += 5;
        }

        &input[..write_idx]
    }
}

mod udp {
    pub struct Packet<'a> {
        pub src: std::net::SocketAddrV4,
        pub dst: std::net::SocketAddrV4,

        /// This is the full length of the packet including headers.
        pub len: usize,

        pub data: &'a [u8],
    }

    pub fn read_packet(buffer: &[u8]) -> Result<Packet<'_>, usize> {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let ip4_header = &buffer[..20];
        assert_eq!(ip4_header[0] >> 4, 4);
        assert_eq!(ip4_header[0] & 0xF, 5);

        let ip4_length = u16::from_be_bytes([ip4_header[2], ip4_header[3]]);
        assert!(ip4_length >= 20);
        let udp_header = &buffer[20..28];

        let ip4_checksum = u16::from_be_bytes([ip4_header[10], ip4_header[11]]);
        let ip4_computed_checksum = packet_header_checksum(ip4_header.iter().copied(), 10);
        if ip4_checksum != ip4_computed_checksum {
            return Err(ip4_length as usize);
        }

        let udp_length = u16::from_be_bytes([udp_header[4], udp_header[5]]);
        let udp_checksum = u16::from_be_bytes([udp_header[6], udp_header[7]]);
        if udp_checksum != 0 {
            let pseudo_header = [
                // source address:
                ip4_header[12],
                ip4_header[13],
                ip4_header[14],
                ip4_header[15],
                // destination address:
                ip4_header[16],
                ip4_header[17],
                ip4_header[18],
                ip4_header[19],
                // zero
                0,
                // protocol
                ip4_header[9],
                // length
                udp_header[4],
                udp_header[5],
            ];

            let checksum_it = pseudo_header
                .iter()
                .chain((&buffer[20..(20 + udp_length as usize)]).iter())
                .copied();
            let udp_computed_checksum = packet_header_checksum(checksum_it, 18);
            if udp_checksum != udp_computed_checksum {
                return Err(ip4_length as usize);
            }
        }

        if udp_length < 8 || udp_length - 8 != ip4_length - 28 {
            return Err(ip4_length as usize);
        }

        let src_addr = Ipv4Addr::new(
            ip4_header[12],
            ip4_header[13],
            ip4_header[14],
            ip4_header[15],
        );

        let dst_addr = Ipv4Addr::new(
            ip4_header[16],
            ip4_header[17],
            ip4_header[18],
            ip4_header[19],
        );

        let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
        let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);

        let data = &buffer[28..(28 + udp_length as usize - 8)];

        return Ok(Packet {
            src: SocketAddrV4::new(src_addr, src_port),
            dst: SocketAddrV4::new(dst_addr, dst_port),
            len: ip4_length as usize,
            data,
        });
    }

    fn packet_header_checksum(mut it: impl Iterator<Item = u8>, skip: usize) -> u16 {
        let mut sum = 0;

        let mut idx = 0;
        loop {
            // Skip the checksum.
            if idx == skip {
                if it.next().is_some() && it.next().is_some() {
                    idx += 2;
                    continue;
                } else {
                    break;
                }
            }

            if let Some(lo) = it.next() {
                if let Some(hi) = it.next() {
                    sum += u16::from_be_bytes([lo, hi]) as u32;
                } else {
                    sum += u16::from_be_bytes([lo, 0]) as u32;
                    break;
                }
                idx += 2;
            } else {
                break;
            }
        }
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        !(sum as u16)
    }
}

mod aes_ext {
    /// Unwrap a 256bit key that was wrapped using the AES Key Wrapping algorithm.
    pub fn unwrap_key256(kek: &[u8], iv: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) {
        assert!(kek.len() == 32);
        assert!(iv.len() == 8);
        assert!(ciphertext.len() == 40);
        assert!(plaintext.len() == 32);

        const N: usize = 4; // 40 bytes = 5 64bit values; n = 5 - 1
        let mut a = get64(ciphertext, 0);
        let mut r = [
            0,
            get64(ciphertext, 1),
            get64(ciphertext, 2),
            get64(ciphertext, 3),
            get64(ciphertext, 4),
        ];

        for j in (0..=5).rev() {
            for i in (1..=N).rev() {
                let t = N as u64 * j as u64 + i as u64;
                let b = aes_concat64_decrypt256(kek, a ^ t, r[i]);
                a = msb(b);
                r[i] = lsb(b);
            }
        }

        assert!(a == get64(iv, 0), "invalid IV");
        (&r[1..])
            .iter()
            .enumerate()
            .for_each(|(idx, &v)| set64(plaintext, idx, v));
    }

    fn msb(n: u128) -> u64 {
        (n >> 64) as u64
    }

    fn lsb(n: u128) -> u64 {
        n as u64
    }

    fn concat64(hi: u64, lo: u64) -> u128 {
        ((hi as u128) << 64) | lo as u128
    }

    fn aes_concat64_decrypt256(key: &[u8], hi: u64, lo: u64) -> u128 {
        use aes::Aes256;
        use block_modes::block_padding::NoPadding;
        use block_modes::{BlockMode, Ecb};

        assert!(key.len() == 32);
        let cipher = Ecb::<Aes256, NoPadding>::new_var(key, Default::default()).unwrap();
        let mut buffer = concat64(hi, lo).to_be_bytes();

        cipher.decrypt(&mut buffer).unwrap();
        return u128::from_be_bytes(buffer);
    }

    fn set64(slice: &mut [u8], index: usize, value: u64) {
        let off = index * 8;
        (&mut slice[off..(off + 8)]).copy_from_slice(&mut value.to_be_bytes());
    }

    fn get64(slice: &[u8], index: usize) -> u64 {
        let off = index * 8;
        let mut out = [0u8; 8];
        out.copy_from_slice(&slice[off..(off + 8)]);
        u64::from_be_bytes(out)
    }
}
