# MCBRS-NetherNet

Framework de serveur **Minecraft Bedrock** en Rust (dans l'esprit de PocketMine-MP).

Ce dépôt contient pour l'instant la couche **MCBRS NetherNet** : le transport WebRTC
utilisé par Minecraft, côté serveur, avec la signalisation HTTP. Le protocole de jeu
(paquets, mondes, blocs, entités, collisions…) viendra plus tard, dans d'autres crates.

```
mcbrs/
├── Cargo.toml                 # workspace
└── crates/
    └── mcbrs-nethernet/        # NetherNet : signalisation HTTP + WebRTC + framing
        ├── src/
        │   ├── signaling.rs   # GET /v1/join, POST /v1/join/{networkId}
        │   ├── host.rs        # PeerConnection côté serveur, NetherNetListener
        │   ├── conn.rs        # NetherNetConnection (canaux reliable / unreliable)
        │   ├── framing.rs     # en-tête 1 octet + fragmentation / réassemblage
        │   ├── sdp.rs         # a=identity, a=fingerprint, a=max-message-size
        │   ├── config.rs      # NetherNetConfig, ServerInfo, ClientAuth, Authorizer
        │   └── identity/      # assertions a=identity (JWT + JWS détaché, ES384)
        ├── examples/nethernet_server.rs
        └── tests/end_to_end.rs
```

## Ce qui est implémenté (guide « NetherNet HTTP Signaling »)

| Section | Contenu |
|---|---|
| §4 | `GET /v1/join` (infos serveur en JSON) et `POST /v1/join/{networkId}` (offre SDP → réponse SDP), une seule requête, sans retry, codes 2xx / 4xx / 5xx |
| §5.1 | Validation de l'assertion client : décodage de l'enveloppe, vérification du `GameServerToken` (via un `TokenVerifier` configurable), JWS détaché sur les `a=fingerprint` en JSON canonique, puis suppression de `a=identity` avant `setRemoteDescription` |
| §5.2 | Assertion serveur **toujours** ajoutée à la réponse : JWT auto-signé contenant `cpk` (JWK P-384), `iat`, `exp`, `iss` + JWS détaché sur les empreintes ; clé opérateur persistante (PEM PKCS#8) |
| §6 | PeerConnection : UDP uniquement, `max-bundle`, ICE complet (sans trickle), sans STUN/TURN, canaux `ReliableDataChannel` et `UnreliableDataChannel` |
| §6.1 | En-tête de 1 octet, fragmentation à compte à rebours (canal fiable uniquement), messages trop gros refusés sur le canal non fiable |
| §7 | Flux complet ; candidats `srflx` injectés via `public_ips` quand le serveur est derrière un NAT 1:1 |
| §9 | NetworkID traité comme une chaîne opaque |

## Utilisation

```rust
use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};

#[tokio::main]
async fn main() -> mcbrs_nethernet::Result<()> {
    let identity = ServerIdentity::load_or_generate("nethernet_server_key.pem")?;
    let listener = NetherNetListener::bind(
        "0.0.0.0:8080",
        NetherNetConfig::default(),
        identity,
        ServerInfo::default(),
    )
    .await?;

    while let Some(conn) = listener.accept().await {
        tokio::spawn(async move {
            while let Some(msg) = conn.recv().await {
                // msg.channel = Reliable | Unreliable, msg.payload = paquet du jeu
                let _ = conn.send(&msg.payload).await;
            }
        });
    }
    Ok(())
}
```

Lancer le serveur d'exemple (écho) :

```bash
cargo run --example nethernet_server -- 0.0.0.0:8080
```

### Authentification des joueurs

Les clés publiques du service d'authentification Minecraft ne figurent pas dans le guide.
La vérification du `GameServerToken` passe donc par le trait `TokenVerifier` :

- `JwkSetVerifier` : vérifie avec un JWKS que vous fournissez (`kid`, `iss`, `aud`, `exp`/`nbf`) ;
- `InsecureTokenDecoder` : **dev uniquement**, ne vérifie pas la signature du token ;
- `ClientAuth::Disabled` / `Optional` / `Required` choisit la politique, et `Authorizer`
  permet d'ajouter allowlist, bans, limite de joueurs, etc.

### Production

- Mettez la signalisation derrière **HTTPS** (reverse proxy Caddy/nginx vers le port HTTP).
  Le client fait alors confiance au certificat TLS et n'affiche pas de demande de confiance (TOFU).
- Gardez `nethernet_server_key.pem` secret et **stable**, et partagez-le entre tous vos serveurs.
  Changer la clé redéclenche la demande de confiance chez les joueurs en HTTP simple.
- Derrière un NAT, renseignez `public_ips` et ouvrez l'UDP entrant : chaque connexion
  utilise des ports UDP éphémères.

## Développement

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

> **Windows** : si le chemin du projet est très long (plus de 260 caractères au total),
> l'éditeur de liens MSVC échoue avec `LNK1104`. Placez le projet dans un chemin court
> ou définissez `CARGO_TARGET_DIR` vers un dossier court (par ex. `C:\cargo-target`).

## Licence

MIT — voir [LICENSE](LICENSE).
