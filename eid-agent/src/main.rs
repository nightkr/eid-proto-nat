use std::{path::PathBuf, pin::pin, sync::Arc};

use clap::Parser;
use eid_agent_proto::{ChallengeResponse, Encrypted, Request, Response, RpcMsg, Signed};
use futures::{Sink, SinkExt, Stream, TryFutureExt, TryStreamExt};
use ring::{rand::SystemRandom, signature::Ed25519KeyPair};
use tokio::{fs, net::TcpListener};
use tracing::Instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(clap::Parser)]
struct Opts {
    #[clap(long)]
    key: PathBuf,
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
    let keypair = Arc::new(Ed25519KeyPair::from_pkcs8_maybe_unchecked(
        &fs::read(&opts.key).await?,
    )?);
    let rng = SystemRandom::new();
    let listener = TcpListener::bind(("127.0.0.1", 9187)).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    loop {
        let (sock, peer) = listener.accept().await?;
        let keypair = keypair.clone();
        let rng = rng.clone();
        tokio::spawn(
            async move {
                tracing::info!("new connection");
                let sock = tokio_tungstenite::accept_async(sock).await?;
                handle_socket(sock, &rng, &keypair).await
            }
            .unwrap_or_else(|error: color_eyre::Report| {
                tracing::error!(?error, "error processing connection")
            })
            .instrument(tracing::info_span!("client connection", %peer)),
        );
    }
}

async fn handle_socket<S>(
    sock: S,
    rng: &SystemRandom,
    keypair: &Ed25519KeyPair,
) -> color_eyre::Result<()>
where
    S: Stream<Item = tungstenite::Result<tungstenite::Message>>
        + Sink<tungstenite::Message, Error = tungstenite::Error>,
{
    let mut sock = pin!(sock);
    loop {
        let Some(req) = sock.try_next().await? else {
            break Ok(());
        };
        if req.is_empty() {
            continue;
        }
        let req = serde_json::from_slice::<RpcMsg<Request>>(&req.into_data())?;
        tracing::debug!(?req, "received request");
        let res: Response = match req.msg {
            Request::Ping => Response::Ok,
            Request::Identify { challenge } => {
                let challenge = challenge.verify()?;
                // TODO: prompt user for confirmation
                let response = ChallengeResponse {
                    nonce: challenge.nonce,
                };

                Response::SignedChallenge {
                    response_token: Encrypted::encrypt(
                        &Signed::sign(&response, keypair)?,
                        rng,
                        challenge.challenger_session_key_public,
                        challenge.nonce,
                    )?,
                }
            }
        };
        let res = RpcMsg {
            id: req.id,
            msg: res,
        };
        tracing::debug!(?res, "sending response");
        sock.send(tungstenite::Message::text(serde_json::to_string(&res)?))
            .await?;
    }
}
