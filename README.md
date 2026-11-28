# SC4MP Server

A multiplayer gameserver for the PC videogame [SimCity 4](https://en.wikipedia.org/wiki/SimCity_4). Uses [python 3.8.10](https://www.python.org/downloads/release/python-3810/), [pyinstaller](https://pyinstaller.org/) and [Inno Setup](https://jrsoftware.org/isinfo.php) script. Built to work with the [SC4MP Client](https://github.com/sc4multiplayer/sc4mp-client).


# Installation

Download and run the installer from the [latest release](https://github.com/sc4multiplayer/sc4mp-server/releases/latest).

Alternatively, use the [SC4MP Server Dockerizer](https://github.com/andreRBarata/sc4mp-server-docker) by [andreRBarata](https://github.com/andreRBarata) and deploy your server as a [Docker](https://www.docker.com/) container.


# Docker

The server can be run as a [Docker](https://www.docker.com/) container. An image is published to `ghcr.io/kegsmr/sc4mp-server` for each release, for `linux/amd64` and `linux/arm64`:

```sh
docker run -d --name sc4mp --restart unless-stopped -p 7240:7240 -v sc4mp:/data ghcr.io/kegsmr/sc4mp-server
```

The image is tagged with the version (e.g. `0.9.0`), the minor version (e.g. `0.9`) and `latest`. The `edge` tag is built from the `feature` branch, for testing.

The server directory (config, plugins, regions, databases and backups) is stored in the `/data` volume. Port `7240` must be reachable from the internet for players to connect.

To update, pull the new image and recreate the container. The server's own updater and system tray icon are not used in the container.

```sh
docker pull ghcr.io/kegsmr/sc4mp-server
docker rm -f sc4mp
docker run -d --name sc4mp --restart unless-stopped -p 7240:7240 -v sc4mp:/data ghcr.io/kegsmr/sc4mp-server
```

To build the image yourself instead, use the included `Dockerfile` and `docker-compose.yml`, which maps `/data` to `./data`:

```sh
docker compose up -d
```

For example, a private server with a password:

```yaml
services:
  sc4mp-server:
    image: ghcr.io/kegsmr/sc4mp-server
    ports:
      - "7240:7240"
    volumes:
      - ./data:/data
    environment:
      SC4MP_INFO_SERVER_NAME: "My Private Server"
      SC4MP_SECURITY_PASSWORD_ENABLED: "True"
      SC4MP_SECURITY_PASSWORD: "change-me"
    restart: unless-stopped
```

Any option in `serverconfig.ini` can be overridden with an environment variable named `SC4MP_<SECTION>_<OPTION>`, for example:

| Variable | Config option |
|----------|---------------|
| `SC4MP_NETWORK_PORT` | `[NETWORK] port` |
| `SC4MP_INFO_SERVER_NAME` | `[INFO] server_name` |
| `SC4MP_SECURITY_PASSWORD_ENABLED` | `[SECURITY] password_enabled` |
| `SC4MP_SECURITY_PASSWORD` | `[SECURITY] password` |
| `SC4MP_RULES_CLAIM_DURATION` | `[RULES] claim_duration` |

Environment variables take priority over `serverconfig.ini` and are not written to it. If you change the port, map the same port in `docker-compose.yml` (e.g. `"7241:7241"`) so the server's announced port matches.


# Usage

Follow the instructions included in the `Readme.html` file.


# Compiling

To compile the source code, run the `setup.py` script.


# Protocol

This section is meant for developers using the SC4MP protocol. Here you can find examples of requests and responses from the server, useful for creating a server scanner or client appplication for the SC4MP network.

The SC4MP protocol is a lightweight, binary-framed JSON-based protocol designed for reliable TCP communication between SC4MP clients and servers. All messages begin with a **16-byte fixed header** followed by a variable-length JSON payload.

Communication uses **request-response** semantics — every client request expects a corresponding server response with the same command code.


---

## Message Structure

| Section | Size | Description |
|----------|------|-------------|
| Protocol Identifier | 5 bytes | Always `"SC4MP"` |
| Message Type | 3 bytes | `"Req"` for requests, `"Res"` for responses |
| Command Code | 6 bytes | ASCII command name, null-padded |
| Header Length | 2 bytes | Unsigned short (`H`, little-endian), specifies length of JSON payload (0 for no headers) |
| Headers | Variable | UTF-8 JSON-encoded key-value pairs |

Every response also carries the server's info headers (the same ones as the `Info` response). When a request fails, the response has an `error` header with the reason instead, eg. `{"error": "Incorrect password."}`.

Some commands send more data after the response, either as a **length-prefixed JSON** value (a 4-byte unsigned int, little-endian, giving the length of the UTF-8 JSON that follows) or as raw bytes. File tables are lists of `["<md5>", <filesize>, "<relative_path>"]` entries.

### Authentication

`Save`, `Token`, `Subscr` and `Chat` (and, on private servers, `PlgTbl`, `PlgDat`, `RgnTbl` and `RgnDat`) need these request headers:
```json
{"version": "<client version>", "user_id": "<uuid>", "password": "<password>"}
```
`password` is only checked when the server has one. Clients older than the server's major and minor version are refused.


---

## Commands

### COMMAND_ADD_SERVER (`AddSrv`)
Adds the requesting server to another server’s list. If `host` is empty, the address the request came from is used. Fails if the server isn't discoverable.

**Request:**
```json
{"host": "<hostname>", "port": <port>}
```

**Response:**
```json
{"status": "success"}
```

---

### COMMAND_CHECK_PASSWORD (`ChkPwd`)
Verifies a server password.

**Request:**
```json
{"password": "<password>"}
```

**Response:**
```json
{"status": "success"}  // or {"status": "failure"}
```

---

### COMMAND_INFO (`Info`)
Retrieves general server information.

**Request:**
```json
{}
```

**Response:**
```json
{
  "server_id": "<string>",
  "server_name": "<string>",
  "server_description": "<string>",
  "server_url": "<string>",
  "server_version": "<string>",
  "private": <bool>,
  "password_enabled": <bool>,
  "user_plugins_enabled": <bool>,
  "claim_duration": <int or null>,
  "max_region_claims": <int or null>,
  "godmode_filter": <bool>,
  "chat_enabled": <bool>,
  "guest_chat": <bool>,
  "time": "YYYY-MM-DD HH:MM:SS"
}
```

---

### COMMAND_PASSWORD_ENABLED (`PwdEnb`)
Checks if the server requires a password.

**Response:**
```json
{"password_enabled": true}
```

---

### COMMAND_PING (`Ping`)
Verifies connectivity.

**Response:**
```json
{}
```

---

### COMMAND_PLUGINS_TABLE (`PlgTbl`)
Retrieves a list of available plugin files.

**Response:**
```json
{}
```
Followed by the file table as length-prefixed JSON:
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

---

### COMMAND_PLUGINS_DATA (`PlgDat`)
Requests actual plugin data after receiving a plugin table.

**Sequence:**
1. Request, and the server responds with `{}`.
2. The client sends the entries it wants, from the file table, as length-prefixed JSON.
3. The server sends the files' raw data, one after another, in the same order. It closes the connection instead if an entry isn't in its file table.

---

### COMMAND_PRIVATE (`Prv`)
Indicates whether plugin and region access requires authentication.

**Response:**
```json
{"private": true}
```

---

### COMMAND_REGIONS_TABLE (`RgnTbl`)
Retrieves a list of available region files.

**Response:**
```json
{}
```
Followed by the file table as length-prefixed JSON:
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

---

### COMMAND_REGIONS_DATA (`RgnDat`)
Requests actual region data after receiving a region table.

**Sequence:**
1. Request, and the server responds with `{}`.
2. The client sends the entries it wants, from the file table, as length-prefixed JSON.
3. The server sends the files' raw data, one after another, in the same order. It closes the connection instead if an entry isn't in its file table.

---

### COMMAND_SAVE (`Save`)
Pushes a region save to the server.

**Sequence:**
1. Request with the authentication headers, and the server responds with `{}`.
2. The client sends the region name and the size of each savegame as length-prefixed JSON: `["<region>", [<filesize>, ...]]`.
3. The client sends the savegames' raw data, one after another.
4. The server responds again with the result, which is `"ok"` if the save was accepted, or else the reason it wasn't (eg. `"City already claimed."`):
```json
{"result": "ok"}
```

---

### COMMAND_SERVER_LIST (`SrvLst`)
Retrieves the global SC4MP server list. Fails if the server isn't discoverable.

**Response:**
```json
{}
```
Followed by the server list as length-prefixed JSON:
```json
[
  ["<host1>", <port1>],
  ["<host2>", <port2>],
  ...
]
```

---

### COMMAND_USER_ID (`UserId`)
Validates user identity by checking a hashed token.

**Request:**
```json
{"hash": "<sha256(user_id + token)>"} 
```

**Response:**
```json
{"status": "success", "user_id": "<uuid>"}  // or {"status": "failure"}
```

---

### COMMAND_TOKEN (`Token`)
Requests a random token for authentication.

**Request:**
```json
{"user_id": "<uuid>"}
```

**Response:**
```json
{"token": "<random_string>"}
```

---

### COMMAND_TIME (`Time`)
Retrieves the current server time.

**Response:**
```json
{"time": "YYYY-MM-DD HH:MM:SS"}
```

---

### COMMAND_LOADING_BACKGROUND (`LdgBkg`)
Retrieves the loading background image data.

**Response:**
```json
{"size": <integer>}
```
Followed by a binary payload of `<size>` bytes.

---

### COMMAND_SUBSCRIBE (`Subscr`)
Subscribes to the server's events (chat messages, players joining and leaving, and new cities) and keeps the connection open to stream them. Requires the user authentication headers. When the server has a password, players without it can still subscribe as guests if the server allows guest chat.

**Request:**
```json
{"version": "<client version>", "user_id": "<uuid>", "password": "<password>"}
```

**Response:**
```json
{"status": "success"}
```
Followed by a stream of responses on the same connection, each with a list of events (an empty list every few seconds while nothing happens):
```json
{"events": [{"event": "<event type>", ...}, ...]}
```
The first events are the recent chat history, each marked `"history": true`, followed by a `welcome` event. The events are:
```json
{"event": "chat", "user_id": "<uuid>", "name": "<mayor name>", "message": "<text>", "time": <seconds since the epoch>, "city": "<city name>", "region": "<region>"}
{"event": "city_founded", "user_id": "<uuid>", "name": "<mayor name>", "city": "<city name>", "region": "<region>", "coords": [<x>, <y>], "reclaimed": <bool>, "time": <seconds since the epoch>}
{"event": "user_join", "user_id": "<uuid>", "name": "<mayor name>"}
{"event": "user_leave", "user_id": "<uuid>", "name": "<mayor name>"}
{"event": "welcome", "server_name": "<string>", "motd": "<string>"}
```
`city` and `region` on `chat` events are only sent for players who have saved a city, and `motd` only when the server has a message of the day. `reclaimed` is `true` when a player took over another mayor's city.

---

### COMMAND_CHAT (`Chat`)
Sends a chat message to every subscribed player. Requires the user authentication headers (guests may chat if the server allows it). Messages can be up to 500 characters long, and a player can send up to 5 messages every 5 seconds.

**Request:**
```json
{"version": "<client version>", "user_id": "<uuid>", "password": "<password>", "message": "<text>"}
```

**Response:**
```json
{"status": "success"}  // or {"error": "<reason>"}, eg. "You're sending messages too quickly. Wait a few seconds."
```

---
