# MCBRS-NetherNet

Implémentation en Rust de **NetherNet**, le transport réseau WebRTC de Minecraft Bedrock,
côté serveur.

MCBRS-NetherNet fait une seule chose : établir des connexions NetherNet avec des clients
Minecraft et transporter leurs données. Elle s'occupe de la signalisation HTTP, de la
négociation WebRTC, de la vérification d'identité et du découpage des messages.
**Elle ne parle pas le protocole de jeu** : pas de paquets Bedrock, de mondes, de blocs,
d'entités ni de collisions. Vous recevez et envoyez des octets bruts, et c'est à votre
serveur de les interpréter.

## Fonctionnalités

- **Signalisation HTTP** : `GET /v1/join` (infos du serveur) et `POST /v1/join/{networkId}`
  (offre SDP → réponse SDP), en un seul aller-retour.
- **WebRTC** (via [webrtc-rs](https://github.com/webrtc-rs/webrtc)) : UDP uniquement,
  `max-bundle`, ICE complet (sans trickle), sans STUN ni TURN.
- **Deux canaux de données** : `ReliableDataChannel` (ordonné, fiable) et
  `UnreliableDataChannel` (non ordonné, sans retransmission).
- **Framing NetherNet** : en-tête d'un octet, fragmentation et réassemblage automatiques
  sur le canal fiable.
- **Identité du joueur** : vérification de l'assertion `a=identity` du client, c'est-à-dire
  le token d'authentification et la signature des empreintes DTLS.
- **Identité du serveur** : chaque réponse est signée avec la clé de l'opérateur (JWT ES384
  auto-signé), ce que le client exige.
- **Politique d'accès** : hook `Authorizer` pour allowlist, bans ou limite de joueurs,
  appelé avant d'allouer la moindre ressource WebRTC.
- **NAT** : annonce de vos IP publiques en candidats `srflx`.

## Installation

```toml
[dependencies]
mcbrs-nethernet = { git = "https://github.com/MCB-RS/MCBRS-NetherNet" }
tokio = { version = "1", features = ["full"] }
```

Rust **1.88** minimum (édition 2024).

## Démarrage rapide

```rust
use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};

#[tokio::main]
async fn main() -> mcbrs_nethernet::Result<()> {
    // Clé de l'opérateur : générée au premier lancement, puis réutilisée.
    let identity = ServerIdentity::load_or_generate("nethernet_server_key.pem")?;

    let listener = NetherNetListener::bind(
        "0.0.0.0:8080",              // adresse de la signalisation HTTP
        NetherNetConfig::default(),
        identity,
        ServerInfo { name: "Mon serveur".into(), ..Default::default() },
    )
    .await?;

    while let Some(conn) = listener.accept().await {
        tokio::spawn(async move {
            println!("connexion de {}", conn.network_id());
            while let Some(msg) = conn.recv().await {
                // msg.channel : Channel::Reliable ou Channel::Unreliable
                // msg.payload : les octets envoyés par le client
                let _ = conn.send(&msg.payload).await;
            }
        });
    }
    Ok(())
}
```

Un serveur d'exemple complet, qui renvoie chaque message reçu, est fourni :

```bash
cargo run --example nethernet_server -- 0.0.0.0:8080
```

Il accepte une ou plusieurs IP publiques en arguments supplémentaires, par exemple
`-- 0.0.0.0:8080 203.0.113.50`. La variable `NETHERNET_KEY` change le chemin de la clé.

## API

| Type | Rôle |
|---|---|
| `NetherNetListener` | Tout-en-un : serveur HTTP de signalisation + hôte WebRTC. `bind()`, `accept()`, `shutdown()`. |
| `NetherNetHost` | L'hôte WebRTC seul. Il implémente `SignalingHandler`, pour brancher votre propre serveur HTTP ou faire relayer les offres par un serveur de signalisation séparé. |
| `NetherNetConnection` | Une connexion établie : `recv()`, `send()`, `send_unreliable()`, `send_on()`, `close()`, `network_id()`, `identity()`. |
| `ServerIdentity` | Clé de l'opérateur (P-384) : génération, chargement/sauvegarde PEM, signature des réponses, empreinte de la clé. |
| `ServerInfo` | Infos renvoyées par `GET /v1/join`. Modifiables à chaud via `host().update_server_info(...)`. |
| `ClientAuth` | Vérification de l'identité des joueurs : `Disabled`, `Optional(verifier)` ou `Required(verifier)`. |
| `TokenVerifier` | Vérifie le token du joueur. Fournis : `JwkSetVerifier` et `InsecureTokenDecoder` (dev uniquement). |
| `Authorizer` | Hook asynchrone pour accepter ou refuser un joueur (HTTP 403). |

Modules bas niveau, utilisables seuls : `framing` (découpage des messages), `sdp`
(attributs `a=identity` et `a=fingerprint`), `identity` (JWT, JWS détaché, JSON canonique).

### Envoyer des messages

- `send()` passe par le canal fiable. Un message trop grand pour un seul message SCTP est
  découpé automatiquement, jusqu'à 256 fragments.
- `send_unreliable()` passe par le canal non fiable. Ce canal ne fragmente jamais : un message
  trop grand est refusé avec `Error::MessageTooLarge`. Si le client n'a pas ouvert ce canal,
  le message part sur le canal fiable.
- La taille des fragments vaut `min(max_outgoing_message_size, a=max-message-size du client)`.

### Authentifier les joueurs

```rust
use std::sync::Arc;
use mcbrs_nethernet::{ClientAuth, JwkSetVerifier, NetherNetConfig};

let jwks: serde_json::Value = /* clés publiques du service d'authentification */;
let config = NetherNetConfig {
    client_auth: ClientAuth::Required(Arc::new(JwkSetVerifier::from_jwks(&jwks)?)),
    ..Default::default()
};
```

Une fois connecté, `conn.identity()` donne les infos du joueur : `xuid()`, `playfab_id()`,
`uuid()`, `display_name()`, ou n'importe quel champ via `claim("...")`.

## Configuration

Champs de `NetherNetConfig` :

| Champ | Défaut | Description |
|---|---|---|
| `client_auth` | `Disabled` | Vérification de l'identité des joueurs. |
| `authorizer` | `None` | Hook d'autorisation appelé à chaque tentative de connexion. |
| `udp_bind_addrs` | `0.0.0.0:0` | Adresses UDP locales pour WebRTC (port 0 = port éphémère). |
| `public_ips` | `[]` | IP publiques annoncées en candidats `srflx`, si le serveur est derrière un NAT. |
| `include_loopback_candidates` | `false` | Annonce aussi `127.0.0.1` (utile pour les tests locaux). |
| `max_outgoing_message_size` | 65 536 | Taille maximale d'un message SCTP envoyé, en-tête compris. |
| `max_incoming_message_size` | 16 Mio | Taille maximale d'un message reçu, une fois réassemblé. |
| `ice_gathering_timeout` | 5 s | Temps maximal de collecte des candidats ICE avant de répondre. |
| `connect_timeout` | 30 s | Temps maximal entre la réponse et l'ouverture des canaux. |
| `max_pending_connections` | 64 | Connexions en cours de négociation ; au-delà, HTTP 503. |
| `accept_backlog` | 128 | Connexions établies en attente d'un `accept()`. |

## Mise en production

- **Signalisation en HTTPS.** Placez un reverse proxy (Caddy, nginx…) devant le port HTTP.
  En HTTPS, le client fait confiance au certificat TLS et n'affiche aucune demande de
  confiance au joueur. En HTTP simple, il affiche une demande à la première connexion (TOFU).
- **Clé de l'opérateur.** Gardez `nethernet_server_key.pem` secret, ne le changez pas et
  utilisez le même fichier sur tous vos serveurs : la confiance des joueurs est liée à cette
  clé. Changer de clé redéclenche la demande de confiance chez les joueurs en HTTP simple.
  Si vous acceptez le HTTP simple, publiez l'empreinte (`ServerIdentity::key_fingerprint()`)
  sur une page que vos joueurs connaissent.
- **Réseau.** Chaque connexion utilise ses propres ports UDP éphémères : autorisez l'UDP
  entrant. Derrière un NAT, renseignez `public_ips`.

## Fonctionnement

```
Client Minecraft                       MCBRS-NetherNet
     │  GET /v1/join                         │
     │──────────────────────────────────────►│  infos du serveur (JSON)
     │  POST /v1/join/{networkId}            │
     │  (offre SDP + identité du joueur)     │  1. vérifie l'identité, appelle l'Authorizer
     │──────────────────────────────────────►│  2. crée la PeerConnection, collecte l'ICE
     │  200 OK (réponse SDP signée)          │  3. signe la réponse avec la clé opérateur
     │◄──────────────────────────────────────│
     │                                       │
     │═════ ICE → DTLS → SCTP (UDP direct) ══│  4. ouverture des deux canaux
     │                                       │  5. NetherNetConnection livrée à accept()
```

## Limites connues

- **Testé uniquement avec un faux client** (webrtc-rs) qui suit la documentation officielle,
  pas encore avec le vrai client Minecraft.
- **Clés d'authentification** : la documentation ne donne ni les clés publiques du service
  d'authentification Minecraft ni le format exact du token joueur. Le champ `cpk` est accepté
  en JWK ou en SPKI base64, et les noms des champs du joueur (`xid`, `pfid`, `uuid`…) sont
  des suppositions.
- **Pas de HTTPS intégré** : passez par un reverse proxy.
- **Pas de port UDP fixe** : chaque connexion a ses propres ports éphémères.

## Développement

```bash
cargo build
cargo test                                  # tests unitaires + test de bout en bout
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Le test de bout en bout (`tests/end_to_end.rs`) lance un vrai serveur et un faux client
Minecraft en local. Il vérifie toute la séquence : signalisation, identités, ouverture des
canaux, messages fragmentés dans les deux sens et déconnexion.

```
src/
├── lib.rs           point d'entrée, réexports
├── signaling.rs     endpoints HTTP (axum)
├── host.rs          hôte WebRTC, NetherNetListener
├── conn.rs          NetherNetConnection, canaux
├── framing.rs       en-tête, fragmentation, réassemblage
├── sdp.rs           a=identity, a=fingerprint, a=max-message-size
├── config.rs        NetherNetConfig, ServerInfo, ClientAuth, Authorizer
├── error.rs         type Error
└── identity/        JWT / JWS détaché, JSON canonique, identités client et serveur
examples/nethernet_server.rs
tests/end_to_end.rs
```

> **Windows** : si le chemin du projet est très long (plus de 260 caractères au total),
> l'éditeur de liens MSVC échoue avec `LNK1104`. Placez le projet dans un chemin court
> ou définissez `CARGO_TARGET_DIR` vers un dossier court.

## Licence

MIT, voir [LICENSE](LICENSE).
