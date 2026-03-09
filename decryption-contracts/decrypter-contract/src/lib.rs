#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use base64::{engine::general_purpose, Engine};
use ic_bls12_381::{pairing, G1Affine, G2Affine};
use std::io::Read;
use std::io::{self, BufRead, BufReader};
use std::{io::Cursor, str::FromStr};
use stylus_sdk::alloy_primitives::Address;
use stylus_sdk::alloy_sol_types;
use stylus_sdk::call::Call;
use stylus_sdk::msg;
use stylus_sdk::prelude::public;
use stylus_sdk::storage::{StorageAddress, StorageBool};
use stylus_sdk::{
    prelude::{sol_interface, sol_storage},
    stylus_proc::{entrypoint},
};

const MAX_INPUT_LEN: usize = 8192;
const INTRO: &str = "age-encryption.org/v1";
const RECIPIENT_PREFIX: &[u8] = b"->";
const FOOTER_PREFIX: &[u8] = b"---";
const COLUMNS_PER_LINE: usize = 64;
const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;
const KYBER_POINT_LEN: usize = 48;
const CIPHER_V_LEN: usize = 32;
const CIPHER_W_LEN: usize = 32;

struct Header {
    recipients: Vec<Box<Stanza>>,
    mac: Vec<u8>,
}
#[derive(Clone)]
struct Stanza {
    type_: String,
    args: Vec<String>,
    body: Vec<u8>,
}

sol_storage! {
    #[entrypoint]
    pub struct Decrypter {
        StorageAddress ibe_contract_addr;
        StorageAddress mac_contract_addr;
        StorageAddress chacha20_decrypter_contract_addr;
        StorageBool initialized;
    }
}

/// Only this address may call `initialize()`. Set at compile time via env var
const TRUSTED_DEPLOYER: Option<&'static str> = option_env!("DECRYPTER_TRUSTED_DEPLOYER_ADDRESS");
sol_interface! {
    interface IIBE {
        function decrypt(uint8[] memory r_gid, uint8[] memory cv, uint8[] memory cw, uint8[] memory cu) external view returns (uint8[] memory);
    }
    interface IDecrypterChacha20 {
        function decrypter(uint8[] memory key, uint8[] memory nonce, uint8[] memory ciphertext) external pure returns (uint8[] memory);
    }
    interface IMacChacha20 {
        function headermac(uint8[] memory key, uint8[] memory body) external pure returns (uint8[] memory);
    }
}

/// Performs the decryption.
/// The initialize() function can be called once to set the address of the three helper contracts
/// 
/// decrypt() function:
/// # Parameters
///
/// - `c`: A `Vec<u8>` representing the ciphertext to be decrypted.
/// - `skbytes`: A `Vec<u8>` containing the decryption key bytes.
///
/// # Returns
///
/// - `Ok(Vec<u8>)`: If successful, returns a `Vec<u8>` containing the plaintext.
/// - `Err(stylus_sdk::call::Error)`: If an error occurs during decryption, it returns an error from the `stylus_sdk::call::Error` type.
#[public]
impl Decrypter {
    pub fn initialize(
        &mut self,
        ibe_contract_addr: String,
        mac_contract_addr: String,
        chacha20_decrypter_contract_addr: String,
    ) -> Result<(), stylus_sdk::call::Error> {
        if !msg::value().is_zero() { return Err(stylus_sdk::call::Error::Revert(b"NO_VALUE".to_vec())); }
        let trusted = TRUSTED_DEPLOYER
            .ok_or_else(|| {
                stylus_sdk::call::Error::Revert(b"TD_ENV_MISSING".to_vec())
            })?;
        let trusted_addr = Address::from_str(trusted).map_err(|_| {
            stylus_sdk::call::Error::Revert(b"TD_ENV_INVALID".to_vec())
        })?;
        if msg::sender() != trusted_addr {
            return Err(stylus_sdk::call::Error::Revert(
                b"TD_UNAUTH".to_vec(),
            ));
        }
        let initialized = self.initialized.get();
        if initialized {
            return Err(stylus_sdk::call::Error::Revert(
                b"ALREADY_INIT".to_vec(),
            ));
        }
        self.ibe_contract_addr
            .set(Address::from_str(&ibe_contract_addr).map_err(|_| {
                return stylus_sdk::call::Error::Revert(b"BAD_IBE_ADDR".to_vec());
            })?);
        self.mac_contract_addr
            .set(Address::from_str(&mac_contract_addr).map_err(|_| {
                return stylus_sdk::call::Error::Revert(b"BAD_MAC_ADDR".to_vec());
            })?);
        self.chacha20_decrypter_contract_addr.set(
            Address::from_str(&chacha20_decrypter_contract_addr).map_err(|_| {
                return stylus_sdk::call::Error::Revert(b"BAD_C20D_ADDR".to_vec());
            })?,
        );
        if *self.ibe_contract_addr == Address::ZERO
        || *self.mac_contract_addr == Address::ZERO
        || *self.chacha20_decrypter_contract_addr == Address::ZERO
    {
        return Err(stylus_sdk::call::Error::Revert(b"ZERO_ADDR".to_vec()));
    }
        self.initialized.set(true);
        return Ok(());
    }

    pub fn decrypt(
        &mut self,
        c: Vec<u8>,
        skbytes: Vec<u8>,
    ) -> core::result::Result<Vec<u8>, stylus_sdk::call::Error> {
        if !msg::value().is_zero() { return Err(stylus_sdk::call::Error::Revert(b"NO_VALUE".to_vec())); }
        if !self.initialized.get() {
            return Err(stylus_sdk::call::Error::Revert(
                b"NOT_INIT".to_vec(),
            ));
        }
        if c.is_empty() || c.len() > MAX_INPUT_LEN {
            return Err(stylus_sdk::call::Error::Revert(b"C_TOO_LARGE".to_vec()));
        }
        if skbytes.len() != 96 {
            return Err(stylus_sdk::call::Error::Revert(
                b"BAD_G2_LEN".to_vec(),
            ));
        }
        let sk_ct_option = G2Affine::from_compressed(&skbytes.try_into().unwrap());
        if sk_ct_option.is_none().into() {
            return Err(stylus_sdk::call::Error::Revert(
                b"BAD_G2".to_vec(),
            ));
        }
        let sk = sk_ct_option.unwrap();

        let mut cursor = Cursor::new(c);

        let decrypted = decrypter(
            &sk,
            &mut cursor,
            *self.ibe_contract_addr,
            *self.chacha20_decrypter_contract_addr,
            *self.mac_contract_addr,
        );

        decrypted
    }
}

pub fn decrypter<'a>(
    sk: &G2Affine,
    src: &'a mut dyn Read,
    ibe_contract_addr: Address,
    chacha20_decrypter_contract: Address,
    mac_contract_addr: Address,
) -> core::result::Result<Vec<u8>, stylus_sdk::call::Error> {
    let (hdr, mut payload) = parse(src).map_err(|_| stylus_sdk::call::Error::Revert(b"PARSE_ERR".to_vec()))?;
     if hdr.recipients.len() != 1
     || hdr.recipients[0].type_ != "distIBE"
     || !hdr.recipients[0].args.is_empty()
 {
     return Err(stylus_sdk::call::Error::Revert(b"BAD_HDR".to_vec()));
 }
    let file_key = unwrap(sk, &[*hdr.recipients[0].clone()], ibe_contract_addr)?;

    let mac_contract = IMacChacha20 {
        address: mac_contract_addr,
    };
    let mac = mac_contract
        .headermac(
            Call::new(),
            file_key.clone(),
            hdr.recipients[0].clone().body,
        )
        .map_err(|_| stylus_sdk::call::Error::Revert(b"MAC_ERR".to_vec()))?;
    if mac.len() != 32 {
        return Err(stylus_sdk::call::Error::Revert(b"BAD_MAC_LEN".to_vec()));
    }
    if mac.to_vec() != hdr.mac {
        return Err(stylus_sdk::call::Error::Revert(
            b"MAC_MISMATCH".to_vec(),
        ));
    }
    let mut nonce = vec![0u8; 16];

    let _ = payload.read_exact(&mut nonce).map_err(|_| {
        stylus_sdk::call::Error::Revert(b"PAYLOAD_ERR".to_vec())
    })?;

    let mut ciphertext: Vec<u8> = vec![];
    let output = payload.read_to_end(&mut ciphertext);
    if output.is_err() {
        return Err(stylus_sdk::call::Error::Revert(
            b"PAYLOAD_ERR".to_vec(),
        ));
    }
    if ciphertext.len() < 16 {
        return Err(stylus_sdk::call::Error::Revert(b"CIPH_SHORT".to_vec()));
    }
    let chacha20_decrypter = IDecrypterChacha20 {
        address: chacha20_decrypter_contract,
    };
    let msg = chacha20_decrypter
        .decrypter(Call::new(), file_key.clone(), nonce, ciphertext)
        .map_err(|_| {
            stylus_sdk::call::Error::Revert(
                b"C20_ERR".to_vec(),
            )
        });

    msg
}

fn unwrap(
    sk: &G2Affine,
    stanzas: &[Stanza],
    ibe_contract: Address,
) -> core::result::Result<Vec<u8>, stylus_sdk::call::Error> {
    let exp_len = KYBER_POINT_LEN + CIPHER_V_LEN + CIPHER_W_LEN;
    if stanzas.len() != 1 || stanzas[0].body.len() != exp_len {
        return Err(stylus_sdk::call::Error::Revert(
            b"LEN_ERR".to_vec(),
        ));
    }
    let kyber_point = &stanzas[0].body[0..KYBER_POINT_LEN];
    let cipher_v = &stanzas[0].body[KYBER_POINT_LEN..KYBER_POINT_LEN + CIPHER_V_LEN];
    let cipher_w = &stanzas[0].body[KYBER_POINT_LEN + CIPHER_V_LEN..];

    let u_ct = G1Affine::from_compressed(kyber_point.try_into().unwrap());
    if u_ct.is_none().into() { return Err(stylus_sdk::call::Error::Revert(b"BAD_G1".to_vec())); }
    let u: G1Affine = u_ct.unwrap();
    if u.is_identity().into() {
        return Err(stylus_sdk::call::Error::Revert(b"BAD_G1".to_vec()));
    }
    let r_gid = pairing(&u, sk);

    let ibe_contract = IIBE {
        address: ibe_contract,
    };
    let data = ibe_contract.decrypt(
        Call::new(),
        r_gid.to_bytes().to_vec(),
        cipher_v.to_vec(),
        cipher_w.to_vec(),
        u.to_compressed().to_vec(),
    );

    data
}

fn split_args(line: &[u8]) -> (String, Vec<String>) {
    let line_str = String::from_utf8_lossy(line);
    let trimmed_line = line_str.trim_end_matches('\n');
    let parts: Vec<String> = trimmed_line.split_whitespace().map(String::from).collect();

    if !parts.is_empty() {
        (parts[0].clone(), parts[1..].to_vec())
    } else {
        (String::new(), Vec::new())
    }
}

fn decode_string(s: &str) -> io::Result<Vec<u8>> {
    general_purpose::STANDARD_NO_PAD.decode(s)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

fn parse<'a, R: Read + 'a>(input: R) -> io::Result<(Header, Box<dyn Read + 'a>)> {
    let mut rr = BufReader::new(input);
    let mut line = String::new();

    rr.read_line(&mut line)?;
    if line != format!("{}\n", INTRO) && line != format!("{}\r\n", INTRO) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }

    let mut h = Header {
        recipients: Vec::new(),
        mac: Vec::new(),
    };
    let mut r: Option<Stanza> = None;

    loop {
        let mut line_bytes = Vec::new();
        let bytes_read = rr.read_until(b'\n', &mut line_bytes)?;
        if bytes_read == 0 {
            break;
        }

        let line = String::from_utf8_lossy(&line_bytes).into_owned();

        if line.as_bytes().starts_with(FOOTER_PREFIX) {
            let (prefix, args) = split_args(&line.as_bytes());
            if prefix.as_bytes() != FOOTER_PREFIX || args.len() != 1 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let ln = line.trim_end_matches(&['\n','\r'][..]);
            if ln != format!("--- {}", args[0]) {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mac = decode_string(&args[0])?;
            if mac.len() != 32 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            h.mac = mac;
            break;
        } else if line.as_bytes().starts_with(RECIPIENT_PREFIX) {
            r = Some(Stanza {
                type_: String::new(),
                args: Vec::new(),
                body: Vec::new(),
            });
            let (prefix, args) = split_args(&line.as_bytes());
            if prefix.as_str() != "->" || args.is_empty() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let stanza = r.as_mut().unwrap();
            stanza.type_ = args[0].clone();
            stanza.args = args[1..].to_vec();

            h.recipients.push(Box::new(stanza.clone()));
        } else if let Some(_stanza) = r.as_mut() {
            let b = decode_string(&line.trim_end())?;
            if b.len() > BYTES_PER_LINE {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            h.recipients.last_mut().unwrap().body.extend_from_slice(&b);

            if b.len() < BYTES_PER_LINE {
                r = None;
            }
        } else {
            // Reject any non-empty, non-whitespace line outside recognized stanza/footer contexts
            let ln = line.trim_end_matches(&['\n','\r'][..]).trim();
            if !ln.is_empty() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        }
    }
    if h.mac.is_empty() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let payload = if rr.buffer().is_empty() {
        Box::new(rr.into_inner()) as Box<dyn Read>
    } else {
        let buffer = rr.buffer().to_vec();
        let remaining_input = rr.into_inner();
        Box::new(io::Cursor::new(buffer).chain(remaining_input)) as Box<dyn Read>
    };

    Ok((h, payload))
}
