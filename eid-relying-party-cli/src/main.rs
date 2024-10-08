use std::{
    path::PathBuf,
    pin::{pin, Pin},
};

use clap::Parser;
use color_eyre::eyre::{Context, ContextCompat};
use eid_agent_proto::{Challenge, Request, Response, RpcMsg, Signed};
use futures::{Sink, SinkExt, Stream, TryStreamExt};
use openssl::{
    ssl::SslFiletype,
    x509::{
        store::{X509Lookup, X509StoreBuilder},
        X509,
    },
};
use pin_project::pin_project;
use ring::{
    agreement::{self, X25519},
    rand::{self, SystemRandom},
    signature::Ed25519KeyPair,
};
use tokio::fs;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(clap::Parser)]
struct Opts {
    #[clap(long, default_value = "ws://localhost:9187")]
    agent: String,

    #[clap(long)]
    key: PathBuf,
    #[clap(long)]
    cert: PathBuf,
    #[clap(long)]
    ca: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .with(tracing_error::ErrorLayer::default())
        .init();
    let opts = Opts::parse();
    let keypair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&fs::read(&opts.key).await?)?;
    let cert = X509::from_pem(&fs::read(&opts.cert).await?)?;
    let trust_store = {
        let mut builder = X509StoreBuilder::new()?;
        let lookup = builder.add_lookup(X509Lookup::file())?;
        for ca in opts.ca {
            lookup.load_cert_file(ca, SslFiletype::PEM)?;
        }
        builder.build()
    };
    let rng = SystemRandom::new();
    let mut conn = pin!(AgentClient::new(
        tokio_tungstenite::connect_async(&opts.agent).await?.0
    ));
    conn.send_request(Request::Ping).await?;
    let challenger_session_key_private = agreement::EphemeralPrivateKey::generate(&X25519, &rng)?;
    let challenge = Challenge {
        nonce: rand::generate(&rng)?.expose(),
        challenger_session_key_public: challenger_session_key_private
            .compute_public_key()?
            .as_ref()
            .to_vec(),
        certificate: cert.to_der()?,
    };
    let challenge_response = conn
        .send_request(Request::Identify {
            challenge: Signed::sign(&challenge, &keypair)?,
        })
        .await?;
    match challenge_response {
        Response::SignedChallenge { response_token } => {
            let response_token =
                response_token.decrypt(challenger_session_key_private, challenge.nonce)?;
            let (user_cert, response) = response_token.verify(&trust_store)?;
            let identities = user_cert
                .subject_alt_names()
                .into_iter()
                .flatten()
                .filter_map(|name| Some(name.uri()?.to_string()))
                .collect::<Vec<_>>();
            assert_eq!(response.nonce, challenge.nonce);
            tracing::info!(
                nonce = ?response.nonce,
                pubkey = ?response_token.signer_pubkey,
                ?identities,
                "authentication succeeded!"
            );
        }
        res => todo!("unexpected response {res:?}"),
    }
    conn.websocket.close(None).await?;
    Ok(())
}

#[pin_project]
struct AgentClient<S> {
    next_id: u32,
    #[pin]
    websocket: S,
}

impl<S> AgentClient<S>
where
    S: Stream<Item = tungstenite::Result<tungstenite::Message>>
        + Sink<tungstenite::Message, Error = tungstenite::Error>,
{
    fn new(websocket: S) -> Self {
        Self {
            next_id: 0,
            websocket,
        }
    }

    async fn send_request(self: &mut Pin<&mut Self>, req: Request) -> color_eyre::Result<Response> {
        let mut this = self.as_mut().project();
        let id = *this.next_id;
        *this.next_id += 1;
        let req = RpcMsg { id, msg: req };
        this.websocket
            .send(tungstenite::Message::text(serde_json::to_string(&req)?))
            .await?;
        let res = serde_json::from_slice::<RpcMsg<Response>>(
            &this
                .websocket
                .try_next()
                .await?
                .context("connection closed without response")?
                .into_data(),
        )?;
        // in the future: multiplex and route response to the correct listener
        if res.id != id {
            return Err(color_eyre::Report::msg(format!(
                "response id {res_id} did not match request id {id}",
                res_id = res.id
            )))
            .context("desync detected");
        }
        Ok(res.msg)
    }
}
