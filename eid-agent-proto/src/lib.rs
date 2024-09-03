use std::marker::PhantomData;

use openssl::{
    pkey::{Id, PKey},
    x509::X509,
};
use ring::{
    aead::{self, Aad, BoundKey, AES_256_GCM},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair, VerificationAlgorithm, ED25519},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use untrusted::Input;

#[derive(Debug, Deserialize, Serialize)]
pub struct RpcMsg<T> {
    pub id: u32,
    pub msg: T,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Request {
    Ping,
    Identify { challenge: Signed<Challenge> },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Response {
    Ok,
    SignedChallenge {
        response_token: Encrypted<Signed<ChallengeResponse>>,
    },
    RejectedChallenge {},
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Signed<T> {
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
    pub _type: PhantomData<T>,
}

impl<T> Signed<T> {
    pub fn sign(message: &T, keypair: &Ed25519KeyPair) -> color_eyre::Result<Self>
    where
        T: Serialize,
    {
        let message = serde_json::to_vec(&message)?;
        Ok(Self {
            signer_pubkey: keypair.public_key().as_ref().to_vec(),
            signature: keypair.sign(&message).as_ref().to_vec(),
            message,
            _type: PhantomData,
        })
    }

    pub fn verify(&self) -> color_eyre::Result<(X509, T)>
    where
        T: DeserializeOwned + HasCertificate,
    {
        ED25519.verify(
            Input::from(&self.signer_pubkey),
            Input::from(&self.message),
            Input::from(&self.signature),
        )?;
        let message = serde_json::from_slice::<T>(&self.message)?;
        // webpki (and rustls-webpki) don't give access to all certificate fields, so we've got to use openssl (for now)
        let cert = X509::from_der(message.certificate())?;
        assert!(cert.public_key()?.public_eq(
            PKey::public_key_from_raw_bytes(&self.signer_pubkey, Id::ED25519)?.as_ref()
        ));
        // TODO: verify trust
        // TODO: verify key usage
        Ok((cert, message))
    }
}

/// A message type that contains an inner certificate
///
/// The certificate is stored inside of the message, so that it is also signed (preventing an unauthorized user from swapping between certificates using the same pubkey).
pub trait HasCertificate {
    fn certificate(&self) -> &[u8];
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Encrypted<T> {
    pub sender_session_key_public: Vec<u8>,
    pub message: Vec<u8>,
    pub _type: PhantomData<T>,
}

impl<T> Encrypted<T> {
    pub fn encrypt(
        message: &T,
        rng: &SystemRandom,
        recipient_session_key_public: Vec<u8>,
        nonce: [u8; aead::NONCE_LEN],
    ) -> color_eyre::Result<Self>
    where
        T: Serialize,
    {
        let sender_session_key_private = agreement::EphemeralPrivateKey::generate(&X25519, rng)?;
        let sender_session_key_public = sender_session_key_private.compute_public_key()?;
        let session_key = agreement::agree_ephemeral(
            sender_session_key_private,
            &UnparsedPublicKey::new(&X25519, recipient_session_key_public),
            |key| aead::UnboundKey::new(&AES_256_GCM, key),
        )??;
        let mut message = serde_json::to_vec(&message)?;
        let mut sealing_key = aead::SealingKey::new(session_key, NonceManager::new(nonce));
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut message)?;
        Ok(Self {
            sender_session_key_public: sender_session_key_public.as_ref().to_vec(),
            message,
            _type: PhantomData,
        })
    }

    pub fn decrypt(
        &self,
        recipient_session_key_private: EphemeralPrivateKey,
        nonce: [u8; aead::NONCE_LEN],
    ) -> color_eyre::Result<T>
    where
        T: DeserializeOwned,
    {
        let session_key = agreement::agree_ephemeral(
            recipient_session_key_private,
            &UnparsedPublicKey::new(&X25519, &self.sender_session_key_public),
            |key| aead::UnboundKey::new(&AES_256_GCM, key),
        )??;
        let mut opening_key = aead::OpeningKey::new(session_key, NonceManager::new(nonce));
        let mut response_bytes = self.message.clone();
        Ok(serde_json::from_slice::<T>(
            opening_key.open_in_place(Aad::empty(), &mut response_bytes)?,
        )?)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub nonce: [u8; aead::NONCE_LEN],
    pub challenger_session_key_public: Vec<u8>,
    pub certificate: Vec<u8>,
}

impl HasCertificate for Challenge {
    fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChallengeResponse {
    pub nonce: [u8; aead::NONCE_LEN],
    pub certificate: Vec<u8>,
}

impl HasCertificate for ChallengeResponse {
    fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

pub struct NonceManager {
    current: [u8; aead::NONCE_LEN],
}

impl NonceManager {
    pub fn new(initial: [u8; aead::NONCE_LEN]) -> Self {
        Self { current: initial }
    }
}

impl aead::NonceSequence for NonceManager {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        // FIXME: implement
        Ok(aead::Nonce::assume_unique_for_key(self.current))
    }
}
