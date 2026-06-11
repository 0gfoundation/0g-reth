#![allow(missing_docs)]

use crate::{
    error::ECIESErrorImpl,
    mac::{HeaderBytes, MAC},
    util::{hmac_sha256, sha256},
    ECIESError,
};
use aes::{cipher::StreamCipher, Aes256};
use alloy_primitives::{
    bytes::{BufMut, Bytes, BytesMut},
    B128, B256, B512 as PeerId,
};
use alloy_rlp::{Encodable, Rlp, RlpEncodable, RlpMaxEncodedLen};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use ctr::Ctr64BE;
use digest::{crypto_common::KeyIvInit, Digest};
use rand_08::{thread_rng as rng, Rng};
use reth_network_peers::{id2pk, pk2id};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    PublicKey, SecretKey, SECP256K1,
};
use sha2::Sha256;
use sha3::Keccak256;

/// RLPx handshake protocol version. Version 5 enables AES-256-CTR for ECIES handshake
/// encryption (0G extension; standard devp2p uses version 4 with AES-128-CTR).
const PROTOCOL_VERSION: usize = 5;

/// KDF output length for ECIES handshake key derivation: 32-byte encryption key + 16-byte MAC
/// material.
const ECIES_KDF_LEN: usize = 48;

/// Computes the shared secret with ECDH and strips the y coordinate after computing the shared
/// secret.
///
/// This uses the given remote public key and local (ephemeral) secret key to [compute a shared
/// secp256k1 point](secp256k1::ecdh::shared_secret_point) and slices off the y coordinate from the
/// returned pair, returning only the bytes of the x coordinate as a [`B256`].
fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> B256 {
    B256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[..32])
}

/// This is the NIST SP 800-56A Concatenation Key Derivation Function (KDF) using SHA-256.
///
/// Internally this uses [`concat_kdf::derive_key_into`] to derive a key into the given `dest`
/// slice.
///
/// # Panics
/// * If the `dest` is empty
/// * If the `dest` len is greater than or equal to the hash output len * the max counter value. In
///   this case, the hash output len is 32 bytes, and the max counter value is 2^32 - 1. So the dest
///   cannot have a len greater than 32 * 2^32 - 1.
fn kdf(secret: B256, s1: &[u8], dest: &mut [u8]) {
    concat_kdf::derive_key_into::<Sha256>(secret.as_slice(), s1, dest).unwrap();
}

/// Derives AES-256 encryption and MAC keys for the ECIES handshake from a shared ECDH secret.
fn derive_ecies_symmetric_keys(shared_secret: B256) -> RLPxSymmetricKeys {
    let mut key = [0u8; ECIES_KDF_LEN];
    kdf(shared_secret, &[], &mut key);
    let enc_key = B256::from_slice(&key[..32]);
    let mac_key = sha256(&key[32..48]);
    RLPxSymmetricKeys { enc_key, mac_key }
}

pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    remote_public_key: Option<PublicKey>,

    pub(crate) remote_id: Option<PeerId>,

    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    ephemeral_shared_secret: Option<B256>,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: B256,
    remote_nonce: Option<B256>,

    ingress_aes: Option<Ctr64BE<Aes256>>,
    egress_aes: Option<Ctr64BE<Aes256>>,
    ingress_mac: Option<MAC>,
    egress_mac: Option<MAC>,

    init_msg: Option<Bytes>,
    remote_init_msg: Option<Bytes>,

    body_size: Option<usize>,
}

impl core::fmt::Debug for ECIES {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ECIES")
            .field("public_key", &self.public_key)
            .field("remote_public_key", &self.remote_public_key)
            .field("remote_id", &self.remote_id)
            .field("ephemeral_public_key", &self.ephemeral_public_key)
            .field("ephemeral_shared_secret", &self.ephemeral_shared_secret)
            .field("remote_ephemeral_public_key", &self.remote_ephemeral_public_key)
            .field("nonce", &self.nonce)
            .field("remote_nonce", &self.remote_nonce)
            .field("ingress_mac", &self.ingress_mac)
            .field("egress_mac", &self.egress_mac)
            .field("init_msg", &self.init_msg)
            .field("remote_init_msg", &self.remote_init_msg)
            .field("body_size", &self.body_size)
            .finish()
    }
}

fn split_at_mut<T>(arr: &mut [T], idx: usize) -> Result<(&mut [T], &mut [T]), ECIESError> {
    if idx > arr.len() {
        return Err(ECIESErrorImpl::OutOfBounds { idx, len: arr.len() }.into())
    }
    Ok(arr.split_at_mut(idx))
}

/// A parsed `RLPx` encrypted message
///
/// From the devp2p spec, this should help perform the following operations:
///
/// For Bob to decrypt the message `R || iv || c || d`, he derives the shared secret `S = Px` where
/// `(Px, Py) = kB * R` as well as the encryption and authentication keys `kE || kM = KDF(S, 32)`.
///
/// Bob verifies the authenticity of the message by checking whether `d == MAC(sha256(kM), iv ||
/// c)` then obtains the plaintext as `m = AES-256-CTR(kE, iv || c)`.
///
/// 0G extends standard devp2p ECIES (AES-128) by deriving a 32-byte `kE` via `KDF(S, 48)`.
#[derive(Debug)]
pub struct EncryptedMessage<'a> {
    /// The auth data, used when checking the `tag` with HMAC-SHA256.
    ///
    /// This is not mentioned in the `RLPx` spec, but included in implementations.
    ///
    /// See source comments of [`Self::check_integrity`] for more information.
    auth_data: [u8; 2],
    /// The remote secp256k1 public key
    public_key: PublicKey,
    /// The IV, for use in AES during decryption, in the tag check
    iv: B128,
    /// The encrypted data
    encrypted_data: &'a mut [u8],
    /// The message tag
    tag: B256,
}

impl<'a> EncryptedMessage<'a> {
    /// Parse the given `data` into an [`EncryptedMessage`].
    ///
    /// If the data is not long enough to contain the expected fields, this returns an error.
    pub fn parse(data: &mut [u8]) -> Result<EncryptedMessage<'_>, ECIESError> {
        // Auth data is 2 bytes, public key is 65 bytes
        if data.len() < 65 + 2 {
            return Err(ECIESErrorImpl::EncryptedDataTooSmall.into())
        }
        let (auth_data, encrypted) = data.split_at_mut(2);

        // convert the auth data to a fixed size array
        //
        // NOTE: this will not panic because we've already checked that the data is long enough
        let auth_data = auth_data.try_into().unwrap();

        let (pubkey_bytes, encrypted) = encrypted.split_at_mut(65);
        let public_key = PublicKey::from_slice(pubkey_bytes)?;

        // return an error if the encrypted len is currently less than 32
        let tag_index =
            encrypted.len().checked_sub(32).ok_or(ECIESErrorImpl::EncryptedDataTooSmall)?;

        // NOTE: we've already checked that the encrypted data is long enough to contain the
        // encrypted data and tag
        let (data_iv, tag_bytes) = encrypted.split_at_mut(tag_index);

        // NOTE: this will not panic because we are splitting at length minus 32 bytes, which
        // causes tag_bytes to be 32 bytes long
        let tag = B256::from_slice(tag_bytes);

        // now we can check if the encrypted data is long enough to contain the IV
        if data_iv.len() < 16 {
            return Err(ECIESErrorImpl::EncryptedDataTooSmall.into())
        }
        let (iv, encrypted_data) = data_iv.split_at_mut(16);

        // NOTE: this will not panic because we are splitting at 16 bytes
        let iv = B128::from_slice(iv);

        Ok(EncryptedMessage { auth_data, public_key, iv, encrypted_data, tag })
    }

    /// Use the given secret and this encrypted message to derive the shared secret, and use the
    /// shared secret to derive the mac and encryption keys.
    pub fn derive_keys(&self, secret_key: &SecretKey) -> RLPxSymmetricKeys {
        // Perform ECDH to get the shared secret, using the remote public key from the message and
        // the given secret key.
        let x = ecdh_x(&self.public_key, secret_key);
        derive_ecies_symmetric_keys(x)
    }

    /// Use the given ECIES keys to check the message integrity using the contained tag.
    pub fn check_integrity(&self, keys: &RLPxSymmetricKeys) -> Result<(), ECIESError> {
        // The MAC tag check operation described is:
        //
        // d == MAC(sha256(kM), iv || c)
        //
        // NOTE: The RLPx spec does not show here that the `auth_data` is required for checking the
        // tag.
        //
        // Geth refers to SEC 1's definition of ECIES:
        //
        // Encrypt encrypts a message using ECIES as specified in SEC 1, section 5.1.
        //
        // s1 and s2 contain shared information that is not part of the resulting
        // ciphertext. s1 is fed into key derivation, s2 is fed into the MAC. If the
        // shared information parameters aren't being used, they should be nil.
        //
        // ```
        // prefix := make([]byte, 2)
        // binary.BigEndian.PutUint16(prefix, uint16(len(h.wbuf.data)+eciesOverhead))
        //
        // enc, err := ecies.Encrypt(rand.Reader, h.remote, h.wbuf.data, nil, prefix)
        // ```
        let check_tag = hmac_sha256(
            keys.mac_key.as_ref(),
            &[self.iv.as_slice(), self.encrypted_data],
            &self.auth_data,
        );
        if check_tag != self.tag {
            return Err(ECIESErrorImpl::TagCheckDecryptFailed.into())
        }

        Ok(())
    }

    /// Use the given ECIES keys to decrypt the contained encrypted data, consuming the message and
    /// returning the decrypted data.
    pub fn decrypt(self, keys: &RLPxSymmetricKeys) -> &'a mut [u8] {
        let Self { iv, encrypted_data, .. } = self;

        // rename for clarity once it's decrypted
        let decrypted_data = encrypted_data;

        let mut decryptor = Ctr64BE::<Aes256>::new((&keys.enc_key.0).into(), (&*iv).into());
        decryptor.apply_keystream(decrypted_data);
        decrypted_data
    }

    /// Use the given ECIES keys to check the integrity of the message, returning an error if the
    /// tag check fails, and then decrypt the message, returning the decrypted data.
    pub fn check_and_decrypt(self, keys: RLPxSymmetricKeys) -> Result<&'a mut [u8], ECIESError> {
        self.check_integrity(&keys)?;
        Ok(self.decrypt(&keys))
    }
}

/// The symmetric keys derived from an ECIES message.
#[derive(Debug)]
pub struct RLPxSymmetricKeys {
    /// The key used for decryption with AES-256 in CTR mode, using a 64-bit big-endian counter.
    pub enc_key: B256,

    /// The key used for verifying message integrity, specifically with the NIST SP 800-56A Concat
    /// KDF.
    pub mac_key: B256,
}

impl ECIES {
    /// Create a new client with the given static secret key, remote peer id, nonce, and ephemeral
    /// secret key.
    fn new_static_client(
        secret_key: SecretKey,
        remote_id: PeerId,
        nonce: B256,
        ephemeral_secret_key: SecretKey,
    ) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let remote_public_key = id2pk(remote_id)?;
        let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);

        Ok(Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,

            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_msg: None,
            remote_init_msg: None,

            remote_id: Some(remote_id),

            body_size: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
        })
    }

    /// Create a new ECIES client with the given static secret key and remote peer ID.
    pub fn new_client(secret_key: SecretKey, remote_id: PeerId) -> Result<Self, ECIESError> {
        // TODO(rand): use rng for nonce
        let mut rng = rng();
        let nonce = B256::random();
        let ephemeral_secret_key = SecretKey::new(&mut rng);
        Self::new_static_client(secret_key, remote_id, nonce, ephemeral_secret_key)
    }

    /// Create a new server with the given static secret key, remote peer id, and ephemeral secret
    /// key.
    pub fn new_static_server(
        secret_key: SecretKey,
        nonce: B256,
        ephemeral_secret_key: SecretKey,
    ) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);

        Ok(Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,

            remote_public_key: None,
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_msg: None,
            remote_init_msg: None,

            remote_id: None,

            body_size: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
        })
    }

    /// Create a new ECIES server with the given static secret key.
    pub fn new_server(secret_key: SecretKey) -> Result<Self, ECIESError> {
        let mut rng = rng();
        let nonce = B256::random();
        let ephemeral_secret_key = SecretKey::new(&mut rng);
        Self::new_static_server(secret_key, nonce, ephemeral_secret_key)
    }

    /// Return the contained remote peer ID.
    pub const fn remote_id(&self) -> PeerId {
        self.remote_id.unwrap()
    }

    fn encrypt_message(&self, data: &[u8], out: &mut BytesMut) {
        let mut rng = rng();

        out.reserve(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data.len() + 32);

        let secret_key = SecretKey::new(&mut rng);
        out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &secret_key).serialize_uncompressed(),
        );

        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        let RLPxSymmetricKeys { enc_key, mac_key } = derive_ecies_symmetric_keys(x);

        let iv = B128::random();
        let mut encryptor = Ctr64BE::<Aes256>::new((&enc_key.0).into(), (&iv.0).into());

        let mut encrypted = data.to_vec();
        encryptor.apply_keystream(&mut encrypted);

        let total_size: u16 = u16::try_from(65 + 16 + data.len() + 32).unwrap();

        let tag =
            hmac_sha256(mac_key.as_ref(), &[iv.as_slice(), &encrypted], &total_size.to_be_bytes());

        out.extend_from_slice(iv.as_slice());
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(tag.as_ref());
    }

    fn decrypt_message<'a>(&self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        // parse the encrypted message from bytes
        let encrypted_message = EncryptedMessage::parse(data)?;

        // derive keys from the secret key and the encrypted message
        let keys = encrypted_message.derive_keys(&self.secret_key);

        // check message integrity and decrypt the message
        encrypted_message.check_and_decrypt(keys)
    }

    fn create_auth_unencrypted(&self) -> BytesMut {
        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        let msg = x ^ self.nonce;
        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest(msg.0),
                &self.ephemeral_secret_key,
            )
            .serialize_compact();

        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig);
        sig_bytes[64] = i32::from(rec_id) as u8;

        let id = pk2id(&self.public_key);

        #[derive(RlpEncodable)]
        struct S<'a> {
            sig_bytes: &'a [u8; 65],
            id: &'a PeerId,
            nonce: &'a B256,
            protocol_version: u8,
        }

        let mut out = BytesMut::new();
        S {
            sig_bytes: &sig_bytes,
            id: &id,
            nonce: &self.nonce,
            protocol_version: PROTOCOL_VERSION as u8,
        }
        .encode(&mut out);

        out.resize(out.len() + rng().gen_range(100..=300), 0);
        out
    }

    #[cfg(test)]
    fn create_auth(&mut self) -> BytesMut {
        let mut buf = BytesMut::new();
        self.write_auth(&mut buf);
        buf
    }

    /// Write an auth message to the given buffer.
    pub fn write_auth(&mut self, buf: &mut BytesMut) {
        let unencrypted = self.create_auth_unencrypted();

        let mut out = buf.split_off(buf.len());
        out.put_u16(0);

        let mut encrypted = out.split_off(out.len());
        self.encrypt_message(&unencrypted, &mut encrypted);

        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        out[..len_bytes.len()].copy_from_slice(&len_bytes);

        out.unsplit(encrypted);

        self.init_msg = Some(Bytes::copy_from_slice(&out));

        buf.unsplit(out);
    }

    fn parse_auth_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let mut data = Rlp::new(data)?;

        let sigdata = data.get_next::<[u8; 65]>()?.ok_or(ECIESErrorImpl::InvalidAuthData)?;
        let signature = RecoverableSignature::from_compact(
            &sigdata[..64],
            RecoveryId::try_from(sigdata[64] as i32)?,
        )?;
        let remote_id = data.get_next()?.ok_or(ECIESErrorImpl::InvalidAuthData)?;
        self.remote_id = Some(remote_id);
        self.remote_public_key = Some(id2pk(remote_id)?);
        self.remote_nonce = Some(data.get_next()?.ok_or(ECIESErrorImpl::InvalidAuthData)?);

        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        self.remote_ephemeral_public_key = Some(SECP256K1.recover_ecdsa(
            &secp256k1::Message::from_digest((x ^ self.remote_nonce.unwrap()).0),
            &signature,
        )?);
        self.ephemeral_shared_secret =
            Some(ecdh_x(&self.remote_ephemeral_public_key.unwrap(), &self.ephemeral_secret_key));

        Ok(())
    }

    /// Read and verify an auth message from the input data.
    #[tracing::instrument(skip_all)]
    pub fn read_auth(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_auth_unencrypted(unencrypted)
    }

    /// Create an `ack` message using the internal nonce, local ephemeral public key, and `RLPx`
    /// ECIES protocol version.
    fn create_ack_unencrypted(&self) -> impl AsRef<[u8]> {
        #[derive(RlpEncodable, RlpMaxEncodedLen)]
        struct S {
            id: PeerId,
            nonce: B256,
            protocol_version: u8,
        }

        alloy_rlp::encode_fixed_size(&S {
            id: pk2id(&self.ephemeral_public_key),
            nonce: self.nonce,
            protocol_version: PROTOCOL_VERSION as u8,
        })
    }

    #[cfg(test)]
    pub fn create_ack(&mut self) -> BytesMut {
        let mut buf = BytesMut::new();
        self.write_ack(&mut buf);
        buf
    }

    /// Write an `ack` message to the given buffer.
    pub fn write_ack(&mut self, out: &mut BytesMut) {
        let mut buf = out.split_off(out.len());

        // reserve space for length
        buf.put_u16(0);

        // encrypt and append
        let mut encrypted = buf.split_off(buf.len());
        self.encrypt_message(self.create_ack_unencrypted().as_ref(), &mut encrypted);
        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        buf.unsplit(encrypted);

        // write length
        buf[..len_bytes.len()].copy_from_slice(&len_bytes[..]);

        self.init_msg = Some(buf.clone().freeze());
        out.unsplit(buf);

        self.setup_frame(true);
    }

    /// Parse the incoming `ack` message from the given `data` bytes, which are assumed to be
    /// unencrypted. This parses the remote ephemeral pubkey and nonce from the message, and uses
    /// ECDH to compute the shared secret. The shared secret is the x coordinate of the point
    /// returned by ECDH.
    ///
    /// This sets the `remote_ephemeral_public_key` and `remote_nonce`, and
    /// `ephemeral_shared_secret` fields in the ECIES state.
    fn parse_ack_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let mut data = Rlp::new(data)?;
        self.remote_ephemeral_public_key =
            Some(id2pk(data.get_next()?.ok_or(ECIESErrorImpl::InvalidAckData)?)?);
        self.remote_nonce = Some(data.get_next()?.ok_or(ECIESErrorImpl::InvalidAckData)?);

        self.ephemeral_shared_secret =
            Some(ecdh_x(&self.remote_ephemeral_public_key.unwrap(), &self.ephemeral_secret_key));
        Ok(())
    }

    /// Read and verify an ack message from the input data.
    #[tracing::instrument(skip_all)]
    pub fn read_ack(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_ack_unencrypted(unencrypted)?;
        self.setup_frame(false);
        Ok(())
    }

    fn setup_frame(&mut self, incoming: bool) {
        let mut hasher = Keccak256::new();
        for el in &if incoming {
            [self.nonce, self.remote_nonce.unwrap()]
        } else {
            [self.remote_nonce.unwrap(), self.nonce]
        } {
            hasher.update(el);
        }
        let h_nonce = B256::from(hasher.finalize().as_ref());

        let iv = B128::default();
        let shared_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(h_nonce.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };

        let aes_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(shared_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };
        self.ingress_aes = Some(Ctr64BE::<Aes256>::new((&aes_secret.0).into(), (&iv.0).into()));
        self.egress_aes = Some(Ctr64BE::<Aes256>::new((&aes_secret.0).into(), (&iv.0).into()));

        let mac_secret: B256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(aes_secret.0.as_ref());
            B256::from(hasher.finalize().as_ref())
        };
        self.ingress_mac = Some(MAC::new(mac_secret));
        self.ingress_mac.as_mut().unwrap().update((mac_secret ^ self.nonce).as_ref());
        self.ingress_mac.as_mut().unwrap().update(self.remote_init_msg.as_ref().unwrap());
        self.egress_mac = Some(MAC::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.remote_nonce.unwrap()).as_ref());
        self.egress_mac.as_mut().unwrap().update(self.init_msg.as_ref().unwrap());
    }

    #[cfg(test)]
    fn create_header(&mut self, size: usize) -> BytesMut {
        let mut out = BytesMut::new();
        self.write_header(&mut out, size);
        out
    }

    pub fn write_header(&mut self, out: &mut BytesMut, size: usize) {
        let mut buf = [0u8; 8];
        BigEndian::write_uint(&mut buf, size as u64, 3);
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(&[194, 128, 128]);

        let mut header = HeaderBytes::from(header);
        self.egress_aes.as_mut().unwrap().apply_keystream(&mut header);
        self.egress_mac.as_mut().unwrap().update_header(&header);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.reserve(Self::header_len());
        out.extend_from_slice(&header[..]);
        out.extend_from_slice(tag.as_slice());
    }

    /// Reads the `RLPx` header from the slice, setting up the MAC and AES, returning the body
    /// size contained in the header.
    pub fn read_header(&mut self, data: &mut [u8]) -> Result<usize, ECIESError> {
        // If the data is not large enough to fit the header and mac bytes, return an error
        //
        // The header is 16 bytes, and the mac is 16 bytes, so the data must be at least 32 bytes
        if data.len() < 32 {
            return Err(ECIESErrorImpl::InvalidHeader.into())
        }

        let (header_bytes, mac_bytes) = split_at_mut(data, 16)?;
        let header = HeaderBytes::from_mut_slice(header_bytes);
        let mac = B128::from_slice(&mac_bytes[..16]);

        self.ingress_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESErrorImpl::TagCheckHeaderFailed.into())
        }

        self.ingress_aes.as_mut().unwrap().apply_keystream(header);
        if header.as_slice().len() < 3 {
            return Err(ECIESErrorImpl::InvalidHeader.into())
        }

        let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)?;

        self.body_size = Some(body_size);

        Ok(body_size)
    }

    pub const fn header_len() -> usize {
        32
    }

    pub const fn body_len(&self) -> usize {
        let len = self.body_size.unwrap();
        Self::align_16(len) + 16
    }

    #[cfg(test)]
    fn create_body(&mut self, data: &[u8]) -> BytesMut {
        let mut out = BytesMut::new();
        self.write_body(&mut out, data);
        out
    }

    pub fn write_body(&mut self, out: &mut BytesMut, data: &[u8]) {
        let len = Self::align_16(data.len());
        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        self.egress_aes.as_mut().unwrap().apply_keystream(encrypted);
        self.egress_mac.as_mut().unwrap().update_body(encrypted);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.extend_from_slice(tag.as_slice());
    }

    pub fn read_body<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        // error if the data is too small to contain the tag
        // TODO: create a custom type similar to EncryptedMessage for parsing, checking MACs, and
        // decrypting the body
        let mac_index = data.len().checked_sub(16).ok_or(ECIESErrorImpl::EncryptedDataTooSmall)?;
        let (body, mac_bytes) = split_at_mut(data, mac_index)?;
        let mac = B128::from_slice(mac_bytes);
        self.ingress_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESErrorImpl::TagCheckBodyFailed.into())
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let ret = body;
        self.ingress_aes.as_mut().unwrap().apply_keystream(ret);
        Ok(split_at_mut(ret, size)?.0)
    }

    /// Returns `num` aligned to 16.
    ///
    /// `<https://stackoverflow.com/questions/14561402/how-is-this-size-alignment-working>`
    #[inline]
    const fn align_16(num: usize) -> usize {
        (num + (16 - 1)) & !(16 - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, hex};

    #[test]
    fn ecdh() {
        let our_secret_key = SecretKey::from_slice(&hex!(
            "202a36e24c3eb39513335ec99a7619bad0e7dc68d69401b016253c7d26dc92f8"
        ))
        .unwrap();
        let remote_public_key = id2pk(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666").into()).unwrap();

        assert_eq!(
            ecdh_x(&remote_public_key, &our_secret_key),
            hex!("821ce7e01ea11b111a52b2dafae8a3031a372d83bdf1a78109fa0783c2b9d5d3")
        )
    }

    #[test]
    fn communicate() {
        let mut rng = rng();
        let server_secret_key = SecretKey::new(&mut rng);
        let server_public_key = PublicKey::from_secret_key(SECP256K1, &server_secret_key);
        let client_secret_key = SecretKey::new(&mut rng);

        let mut server_ecies = ECIES::new_server(server_secret_key).unwrap();
        let mut client_ecies =
            ECIES::new_client(client_secret_key, pk2id(&server_public_key)).unwrap();

        // Handshake
        let mut auth = client_ecies.create_auth();
        server_ecies.read_auth(&mut auth).unwrap();
        let mut ack = server_ecies.create_ack();
        client_ecies.read_ack(&mut ack).unwrap();
        let mut ack = client_ecies.create_ack();
        server_ecies.read_ack(&mut ack).unwrap();

        let server_to_client_data = [0u8, 1u8, 2u8, 3u8, 4u8];
        let client_to_server_data = [5u8, 6u8, 7u8];

        // Test server to client 1
        let mut header = server_ecies.create_header(server_to_client_data.len());
        assert_eq!(header.len(), ECIES::header_len());
        client_ecies.read_header(&mut header).unwrap();
        let mut body = server_ecies.create_body(&server_to_client_data);
        assert_eq!(body.len(), client_ecies.body_len());
        let ret = client_ecies.read_body(&mut body).unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test client to server 1
        server_ecies
            .read_header(&mut client_ecies.create_header(client_to_server_data.len()))
            .unwrap();
        let mut b = client_ecies.create_body(&client_to_server_data);
        let ret = server_ecies.read_body(&mut b).unwrap();
        assert_eq!(ret, client_to_server_data);

        // Test server to client 2
        client_ecies
            .read_header(&mut server_ecies.create_header(server_to_client_data.len()))
            .unwrap();
        let mut b = server_ecies.create_body(&server_to_client_data);
        let ret = client_ecies.read_body(&mut b).unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test server to client 3
        client_ecies
            .read_header(&mut server_ecies.create_header(server_to_client_data.len()))
            .unwrap();
        let mut b = server_ecies.create_body(&server_to_client_data);
        let ret = client_ecies.read_body(&mut b).unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test client to server 2
        server_ecies
            .read_header(&mut client_ecies.create_header(client_to_server_data.len()))
            .unwrap();
        let mut b = client_ecies.create_body(&client_to_server_data);
        let ret = server_ecies.read_body(&mut b).unwrap();
        assert_eq!(ret, client_to_server_data);

        // Test client to server 3
        server_ecies
            .read_header(&mut client_ecies.create_header(client_to_server_data.len()))
            .unwrap();
        let mut b = client_ecies.create_body(&client_to_server_data);
        let ret = server_ecies.read_body(&mut b).unwrap();
        assert_eq!(ret, client_to_server_data);
    }

    fn eip8_test_server_key() -> SecretKey {
        SecretKey::from_slice(&hex!(
            "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
        ))
        .unwrap()
    }

    fn eip8_test_client() -> ECIES {
        let client_static_key = SecretKey::from_slice(&hex!(
            "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee"
        ))
        .unwrap();

        let client_ephemeral_key = SecretKey::from_slice(&hex!(
            "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d"
        ))
        .unwrap();

        let client_nonce =
            b256!("0x7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");

        let server_id = pk2id(&PublicKey::from_secret_key(SECP256K1, &eip8_test_server_key()));

        ECIES::new_static_client(client_static_key, server_id, client_nonce, client_ephemeral_key)
            .unwrap()
    }

    fn eip8_test_server() -> ECIES {
        let server_ephemeral_key = SecretKey::from_slice(&hex!(
            "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4"
        ))
        .unwrap();

        let server_nonce =
            b256!("0x559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd");

        ECIES::new_static_server(eip8_test_server_key(), server_nonce, server_ephemeral_key)
            .unwrap()
    }

    #[test]
    /// EIP-8 auth/ack round-trip with protocol version 5 (AES-256-CTR handshake).
    ///
    /// Standard EIP-8 test vectors from <https://eips.ethereum.org/EIPS/eip-8> use AES-128-CTR
    /// and are not applicable after the 0G AES-256 handshake extension.
    fn eip8_handshake_round_trip() {
        let mut test_client = eip8_test_client();
        let mut test_server = eip8_test_server();

        test_server.read_auth(&mut test_client.create_auth()).unwrap();
        test_client.read_ack(&mut test_server.create_ack()).unwrap();
    }

    #[test]
    fn kdf_out_of_bounds() {
        // ensures that the kdf method does not panic if the dest is too small
        let len_range = 1..65;
        for len in len_range {
            let mut dest = vec![1u8; len];
            kdf(
                b256!("0x7000000000000000000000000000000000000000000000000000000000000007"),
                &[0x01, 0x33, 0x70, 0xbe, 0xef],
                &mut dest,
            );
        }
    }
}
