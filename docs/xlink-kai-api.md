# XLink Kai connector API reference

Source artifacts: `xlink-api-recon.tgz` from card `t_e4535822`, live WebUI assets fetched from the engine, and read-only live probes against XLink Kai Engine/7.4.45. This document intentionally redacts no credentials because none were found in the static WebUI bundle. Do not paste `getconfig-response.txt` contents into tickets unless reviewed separately; it is runtime configuration.

## 1. Transport overview

The connector is the WebUI-to-engine HTTP API exposed by `kaiengine` on the host-local listener:

- Base URL from the container/host namespace: `http://127.0.0.1:34522`
- Server header observed by recon: `XLink Kai Engine/7.4.45`
- CORS origin observed by recon: `http://127.0.0.1:1337`
- The listener is host-bound/local by design. Do not expose it directly to the public internet.

### HTTP endpoints

| Endpoint | Method used by WebUI | Body/query | Purpose | Notes |
|---|---:|---|---|---|
| `/connector/attach` | POST | empty body | Create a connector session. | Response is a decimal session id such as `6`. |
| `/connector/command` | POST | `sessionid=<id>&command=<percent-encoded-command>` | Submit one tab-delimited `KAI_CLIENT_*` command. | Synchronous response is usually `OK`; real data arrives through poll. |
| `/connector/poll?sessionid=<id>` | POST | empty body | Long-poll for engine events for that session. | Response is percent-encoded event records separated by byte `0x01`. |
| `/connector/detach?sessionid=<id>` | POST | empty body | End the connector session. | Verified response: `OK`. |
| `/connector/getconfig` | POST/GET in recon | none observed | Return engine config text. | Recon captured it; do not publish secrets from it. |
| `/connector/saveconfig` | POST | `key=value&...` | Save config fields. | WebUI uses this for skin/config writes; not probed because it mutates config. |

The WebUI also uses `KAI_CLIENT_GET_URL` to ask the engine to fetch Team XLink web endpoints under `/connector/webuiconfig.php` on `client.teamxlink.co.uk`. Those are not local connector endpoints, but the returned `KAI_CLIENT_HTTP_RESPONSE` is part of this API's event vocabulary.

### Session lifecycle

1. `POST /connector/attach` -> store the returned session id as `SID`.
2. Submit bootstrap commands: WebUI sends `KAI_CLIENT_GETSTATE` and `KAI_CLIENT_ORBS_AVAILABLE` immediately.
3. Repeatedly `POST /connector/poll?sessionid=$SID`. The WebUI starts the next poll after each successful poll response.
4. Submit commands via `/connector/command` as needed.
5. `POST /connector/detach?sessionid=$SID` when done.

### Wire format quirks

- Command bodies are tab-delimited (`	`), not semicolon-delimited. The debug input in the WebUI replaces typed semicolons with tabs before sending.
- Most commands include a trailing tab after the last argument. Keep it; the UI consistently sends it.
- The whole command string is percent-encoded as the `command=` form field. Current WebUI uses `encodeURIComponent` for engine versions `>= 0x070413` and old `escape()` before that.
- Poll responses are percent-encoded. After decoding, records are separated by byte `0x01` (``). Fields inside each record are semicolon-delimited.
- Chat text escaping differs from command transport: before `KAI_CLIENT_CHAT`, the WebUI converts literal semicolons in chat text to byte `0x02`, and converts `%` to `%25`, then percent-encodes the full command.
- Event records commonly end in a trailing semicolon, leaving an empty final field after `split(';')`.

### Minimal shell pattern

```sh
SID=$(curl -sS -X POST http://127.0.0.1:34522/connector/attach)
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data "sessionid=$SID&command=KAI_CLIENT_GETSTATE%09"
curl -sS -X POST "http://127.0.0.1:34522/connector/poll?sessionid=$SID" | python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()).replace("\x01","\n"))'
curl -sS -X POST "http://127.0.0.1:34522/connector/detach?sessionid=$SID"
```

## 2. Complete command reference

Commands below are every `KAI_CLIENT_*` token discovered in the engine strings plus every command issued or referenced by the WebUI JS. Confidence labels mean:

- `verified`: invoked safely during this task and response shape observed.
- `inferred-from-JS`: command shape came from `webui/js/kaiUI.js`.
- `inferred-from-strings-only`: token appeared in the engine binary strings, but the WebUI did not exercise it in captured code.

| Command | Argument signature | Kind | Example invocation | Example response | Confidence |
|---|---|---|---|---|---|
| `KAI_CLIENT_ACCEPT_FRIEND_REQ` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ACCEPT_FRIEND_REQ%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_ADD_CONTACT` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ADD_CONTACT%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_ADD_FRIEND_REQ` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ADD_FRIEND_REQ%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_APP_SPECIFIC` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_APP_SPECIFIC%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_ARENA_BAN` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ARENA_BAN%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_ARENA_BREAK_STREAM` | `unknown` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ARENA_BREAK_STREAM%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_ARENA_KICK` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ARENA_KICK%09<kaitag>%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_ARENA_PM` | `kaitag, message` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ARENA_PM%09<kaitag>%09<message>%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_ARENA_STATUS` | `status, visibility_flag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ARENA_STATUS%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_ATTACH` | `no args; normally use /connector/attach instead` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ATTACH%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_AVATAR` | `kaitag` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_AVATAR%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_BLOCK_USER` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_BLOCK_USER%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_CANCEL_FRIEND_REQ` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CANCEL_FRIEND_REQ%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_CAPS` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CAPS%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_CHAT` | `message` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CHAT%09Hello%20from%20Kai%20API%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_CHATMODE` | `arena_or_"General Chat"` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CHATMODE%09General%20Chat%09'` | verified empty poll response; UI uses it to select the chat context | verified |
| `KAI_CLIENT_CHAT_LOCK` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CHAT_LOCK%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_CONTACT_PING` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CONTACT_PING%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_CREATE_VECTOR` | `max_players, description_urlencoded, password` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_CREATE_VECTOR%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_DETACH` | `no args; normally use /connector/detach instead` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_DETACH%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_DISCOVER` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_DISCOVER%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_DISMISS_NOTIFICATION` | `notification_id` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_DISMISS_NOTIFICATION%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_GAMECHANNEL` | `unknown game-channel payload` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GAMECHANNEL%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_GETSTATE` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GETSTATE%09'` | raw command response: OK; poll: KAI_CLIENT_LOGGED_IN;\x01KAI_CLIENT_STATUS;XLink Kai is Online..;\x01KAI_CLIENT_USER_DATA;dedihost;... | verified |
| `KAI_CLIENT_GET_BLOCKED_USER_LIST` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_BLOCKED_USER_LIST%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_GET_IGNORED_FRIEND_REQ_LIST` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_IGNORED_FRIEND_REQ_LIST%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_GET_METRICS` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_METRICS%09'` | poll: KAI_CLIENT_METRICS;TX Marathon;Yes;104.156.237.139;30000;7.4.45;Linux x86_64 ...;OPEN; | verified |
| `KAI_CLIENT_GET_NOTIFICATIONS` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_NOTIFICATIONS%09'` | verified empty poll response when no notifications were pending | verified |
| `KAI_CLIENT_GET_PENDING_FRIEND_REQ_LIST` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_PENDING_FRIEND_REQ_LIST%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_GET_PROFILE` | `kaitag` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_PROFILE%09<kaitag>%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_GET_URL` | `host, path_with_query` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_URL%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_GET_VECTORS` | `arena_path` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_GET_VECTORS%09Arena%09'` | poll: KAI_CLIENT_SUB_VECTOR;Arena/XBox/First Person Shooter/Halo 2;12;0;0;0; ... | verified |
| `KAI_CLIENT_IGNORE_FRIEND_REQ` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_IGNORE_FRIEND_REQ%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_INVITE` | `kaitag, arena_path[, optional?]` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_INVITE%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_INVITE_BACKLOG` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_INVITE_BACKLOG%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_LOGIN` | `username, password, password_base64` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_LOGIN%09<username>%09<password>%09<base64(password)>%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_LOGOUT` | `no args` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_LOGOUT%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_NATTEST` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_NATTEST%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_ORBS_AVAILABLE` | `no args` | request; returns poll events | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_ORBS_AVAILABLE%09'` | poll: KAI_CLIENT_ORBS_AVAILABLE;Team XLink Asia;ADVANCED_ASIA;...;TX Marathon;ADVANCED_MARATHON;...; | verified |
| `KAI_CLIENT_PM` | `kaitag, message` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_PM%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_PM_BACKLOG` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_PM_BACKLOG%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_REMOVE_CONTACT` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_REMOVE_CONTACT%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_REMOVE_FRIEND` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_REMOVE_FRIEND%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_SELECT_ORB` | `orb_id` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_SELECT_ORB%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_SPECIFIC_COUNT` | `unknown` | request/command; behavior not verified | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_SPECIFIC_COUNT%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_TAKEOVER` | `unknown` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_TAKEOVER%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_UNBLOCK_USER` | `kaitag` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_UNBLOCK_USER%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-strings-only |
| `KAI_CLIENT_UPGRADE` | `no args` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_UPGRADE%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |
| `KAI_CLIENT_VECTOR` | `arena_path[, password]` | state-changing or user-visible command; response arrives as poll events/side effects | `curl -sS -X POST 'http://127.0.0.1:34522/connector/command' --data 'sessionid=$SID&command=KAI_CLIENT_VECTOR%09Arena%2FXBox%2FFirst%20Person%20Shooter%2FHalo%202%09'` | not safely invoked during this recon; expect command response "OK" and any data/side effect via later /connector/poll | inferred-from-JS |

## 3. Event vocabulary

Poll event records are semicolon-delimited after URL decoding and `` splitting. The table combines live observations and WebUI handlers.

| Event | Evidence |
|---|---|
| `KAI_CLIENT_ADD_CONTACT` | observed in live GETSTATE poll |
| `KAI_CLIENT_ADD_FRIEND_REQ` | handled by WebUI JS |
| `KAI_CLIENT_ADMIN_PRIVILEGES` | observed in live GETSTATE poll |
| `KAI_CLIENT_ARENA_PING` | handled by WebUI JS |
| `KAI_CLIENT_ARENA_PM` | handled by WebUI JS |
| `KAI_CLIENT_ARENA_STATUS` | observed in live GETSTATE poll |
| `KAI_CLIENT_AVATAR` | handled by WebUI JS |
| `KAI_CLIENT_CHAT` | observed in live GETSTATE poll |
| `KAI_CLIENT_CHAT2` | handled by WebUI JS |
| `KAI_CLIENT_CHATMODE` | observed in live GETSTATE poll |
| `KAI_CLIENT_CODEPAGE` | observed in live GETSTATE poll |
| `KAI_CLIENT_COMMUNITY_HELPER_PRIVILEGES` | observed in live GETSTATE poll |
| `KAI_CLIENT_CONNECTED_MESSENGER` | observed in live GETSTATE poll |
| `KAI_CLIENT_CONTACT_OFFLINE` | handled by WebUI JS |
| `KAI_CLIENT_CONTACT_ONLINE` | handled by WebUI JS |
| `KAI_CLIENT_CONTACT_PING` | handled by WebUI JS |
| `KAI_CLIENT_DDS_CONNECTED` | handled by WebUI JS |
| `KAI_CLIENT_DDS_DISCONNECTED` | handled by WebUI JS |
| `KAI_CLIENT_DETACH` | handled by WebUI JS |
| `KAI_CLIENT_DHCP_FAILURE` | handled by WebUI JS |
| `KAI_CLIENT_DHCP_SUCCESS` | observed in live GETSTATE poll |
| `KAI_CLIENT_GAMECHANNEL` | handled by WebUI JS |
| `KAI_CLIENT_HTTP_RESPONSE` | handled by WebUI JS |
| `KAI_CLIENT_INVITE` | handled by WebUI JS |
| `KAI_CLIENT_INVITE_BACKLOG` | handled by WebUI JS |
| `KAI_CLIENT_JOINS_CHAT` | observed in live GETSTATE poll |
| `KAI_CLIENT_JOINS_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_LEAVES_CHAT` | handled by WebUI JS |
| `KAI_CLIENT_LEAVES_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_LOCAL_DEVICE` | observed in live GETSTATE poll |
| `KAI_CLIENT_LOCAL_DEVICE_REMOVE` | handled by WebUI JS |
| `KAI_CLIENT_LOGGED_IN` | observed in live GETSTATE poll |
| `KAI_CLIENT_METRICS` | handled by WebUI JS |
| `KAI_CLIENT_MODERATOR_PRIVILEGES` | observed in live GETSTATE poll |
| `KAI_CLIENT_NOTIFICATION` | handled by WebUI JS |
| `KAI_CLIENT_NOT_LOGGED_IN` | handled by WebUI JS |
| `KAI_CLIENT_ORBS_AVAILABLE` | handled by WebUI JS |
| `KAI_CLIENT_PM` | handled by WebUI JS |
| `KAI_CLIENT_PM_BACKLOG` | handled by WebUI JS |
| `KAI_CLIENT_RELOAD` | handled by WebUI JS |
| `KAI_CLIENT_REMOTE_ARENA_DEVICE` | handled by WebUI JS |
| `KAI_CLIENT_REMOVE_CONTACT` | handled by WebUI JS |
| `KAI_CLIENT_REMOVE_FRIEND` | handled by WebUI JS |
| `KAI_CLIENT_REMOVE_SUB_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_SESSION_KEY` | observed in live GETSTATE poll |
| `KAI_CLIENT_SKIN` | referenced by WebUI JS |
| `KAI_CLIENT_STATUS` | observed in live GETSTATE poll |
| `KAI_CLIENT_SUB_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_SUB_VECTOR_UPDATE` | handled by WebUI JS |
| `KAI_CLIENT_USER_DATA` | observed in live GETSTATE poll |
| `KAI_CLIENT_USER_PROFILE` | handled by WebUI JS |
| `KAI_CLIENT_USER_SUB_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_VECTOR` | handled by WebUI JS |
| `KAI_CLIENT_VETERAN_PRIVILEGES` | observed in live GETSTATE poll |

Important observed event shapes:

- `KAI_CLIENT_LOGGED_IN;`
- `KAI_CLIENT_NOT_LOGGED_IN;<username>;<password>;` (JS expects saved/default fields; do not log passwords)
- `KAI_CLIENT_CODEPAGE;<codepage>;`
- `KAI_CLIENT_SESSION_KEY;<session-key>;`
- `KAI_CLIENT_STATUS;<status-text>;`
- `KAI_CLIENT_USER_DATA;<kaitag>;`
- `KAI_CLIENT_ARENA_STATUS;<status>;<visibility-flag>;`
- `KAI_CLIENT_CHATMODE;<arena-or-General Chat>;`
- `KAI_CLIENT_JOINS_CHAT;<chat-context>;<kaitag>;`
- `KAI_CLIENT_LEAVES_CHAT;<chat-context>;<kaitag>;`
- `KAI_CLIENT_CHAT;<chat-context>;<speaker>;<message>;`
- `KAI_CLIENT_CHAT2;<chat-context>;<speaker>;<message>;`
- `KAI_CLIENT_JOINS_VECTOR;<kaitag>;` / `KAI_CLIENT_LEAVES_VECTOR;<kaitag>;`
- `KAI_CLIENT_SUB_VECTOR;<vector>; <users>; <subs>; <ispass>; <maxplayers>;`
- `KAI_CLIENT_USER_SUB_VECTOR;<vector>; <users>; <subs>; <ispass>; <maxplayers>; <description>;`
- `KAI_CLIENT_SUB_VECTOR_UPDATE;<vector>; <count>; <subs>;`
- `KAI_CLIENT_REMOVE_SUB_VECTOR;<vector>;`
- `KAI_CLIENT_VECTOR;<vector>;`
- `KAI_CLIENT_ARENA_PING;<kaitag>;...` (JS reads player, ping, caps from indexes 1..3)
- `KAI_CLIENT_CONTACT_PING;<kaitag>;...` (JS reads indexes 1,2,3)
- `KAI_CLIENT_USER_PROFILE;<user>; <age>; <bandwidth>; <location>; <xbox>; <gcn>; <ps2>; <bio>; <unused?>; <html-profile>;`
- `KAI_CLIENT_METRICS;<orb>; <reachable>; <public-ip>; <port>; <version>; <platform>; ...; <network-state>;`
- `KAI_CLIENT_NOTIFICATION;<id>; <time>; <priority>; <seen>; <imageURL>; <header>; <body>; <bodyHTML>; <canBeCleared>; <local>;`
- `KAI_CLIENT_HTTP_RESPONSE;<status-or-id>; <url>; <headers?>; <body>;` (WebUI only inspects URL and body for webuiconfig init)
- `KAI_CLIENT_ORBS_AVAILABLE;<name1>;<id1>;<name2>;<id2>;...;`
- `KAI_CLIENT_LOCAL_DEVICE;<mac>; <name>; <console-family>;`
- `KAI_CLIENT_LOCAL_DEVICE_REMOVE;<mac>;`
- `KAI_CLIENT_DHCP_SUCCESS;<mac>; <name>; <console-family>;`
- `KAI_CLIENT_DHCP_FAILURE;<mac>;`
- `KAI_CLIENT_REMOTE_ARENA_DEVICE;<kaitag>; <mac-or-device>; [console-family];`
- privilege lists: `KAI_CLIENT_ADMIN_PRIVILEGES`, `KAI_CLIENT_MODERATOR_PRIVILEGES`, `KAI_CLIENT_VETERAN_PRIVILEGES`, `KAI_CLIENT_COMMUNITY_HELPER_PRIVILEGES` use slash-delimited kaitags in one field.

## 4. State model

`KAI_CLIENT_GETSTATE` is the state snapshot command. A verified decoded poll began:

```text
KAI_CLIENT_LOGGED_IN;
KAI_CLIENT_CODEPAGE;0;
KAI_CLIENT_SESSION_KEY;;
KAI_CLIENT_STATUS;XLink Kai is Online..;
KAI_CLIENT_USER_DATA;dedihost;
KAI_CLIENT_ARENA_STATUS;1;1;
KAI_CLIENT_CONNECTED_MESSENGER;
KAI_CLIENT_CHATMODE;General Chat;
...
```

Read login state from mutually exclusive state events:

- `KAI_CLIENT_LOGGED_IN;` means the engine has an authenticated Kai identity.
- `KAI_CLIENT_NOT_LOGGED_IN;<username>;<password>;` means the WebUI should show the login form. Treat the password field as sensitive if present.
- `KAI_CLIENT_CONNECTED_MESSENGER;` means the messenger/chat backend is connected; WebUI then switches to General Chat.
- `KAI_CLIENT_USER_DATA;<kaitag>;` names the current user (`dedihost` in the snapshot).

Read current chat/arena from:

- `KAI_CLIENT_CHATMODE;<General Chat or arena path>;`
- `KAI_CLIENT_VECTOR;<arena path>;` when switching arenas.
- Player membership for General Chat comes from `KAI_CLIENT_JOINS_CHAT` / `KAI_CLIENT_LEAVES_CHAT`; arena player membership comes from `KAI_CLIENT_JOINS_VECTOR` / `KAI_CLIENT_LEAVES_VECTOR` and ping/device events.
- Arena tree entries come from `KAI_CLIENT_SUB_VECTOR`, `KAI_CLIENT_USER_SUB_VECTOR`, `KAI_CLIENT_SUB_VECTOR_UPDATE`, and `KAI_CLIENT_REMOVE_SUB_VECTOR` after `KAI_CLIENT_GET_VECTORS` or `KAI_CLIENT_VECTOR`.

## 5. Arena path grammar

Arena paths are slash-delimited strings rooted at `Arena`, for example:

```text
Arena/XBox/First Person Shooter/Halo 2
Arena/PlayStation 3/First Person Shooter/Conflict Denied Ops
```

Observed grammar:

```text
path        := "" | segment ("/" segment)*
root        := "Arena"
segment     := display text; spaces and punctuation are literal
private     := user-created vector returned as KAI_CLIENT_USER_SUB_VECTOR
```

Notes:

- The empty vector (`KAI_CLIENT_VECTOR		`) switches back to General Chat in the WebUI.
- `KAI_CLIENT_GET_VECTORS	Arena	` returns child arena paths. `KAI_CLIENT_GET_VECTORS		` returned an empty poll during verification, so use `Arena` for top-level arena listing.
- The WebUI creates breadcrumb links by splitting on `/`. No escaping for literal slash inside a segment was found; assume `/` is reserved as a hierarchy separator.
- Password-protected arenas are signaled by the `ispass` field in `KAI_CLIENT_SUB_VECTOR`; enter with `KAI_CLIENT_VECTOR	<path>	<password>	`.
- Private/user arenas are distinguished in the UI when the event name is `KAI_CLIENT_USER_SUB_VECTOR`; its sixth data field is a URL-encoded description.

## 6. Curl recipes

All recipes assume shell access in the host/container namespace where `127.0.0.1:34522` reaches the engine.

### Attach once

```sh
SID=$(curl -sS -X POST http://127.0.0.1:34522/connector/attach)
```

### Log in

This is inferred from JS and was not invoked during recon:

```sh
USER='<kaitag>'
PASS='<password>'
PASS64=$(printf %s "$PASS" | base64 -w0)
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_LOGIN	$USER	$PASS	$PASS64	"
```

Poll until `KAI_CLIENT_LOGGED_IN` or `KAI_CLIENT_NOT_LOGGED_IN` appears.

### List arenas at a level

Verified for `Arena`:

```sh
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_GET_VECTORS	Arena	"
curl -sS -X POST "http://127.0.0.1:34522/connector/poll?sessionid=$SID"   | python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()).replace("\x01","\n"))'
```

Example decoded rows:

```text
KAI_CLIENT_SUB_VECTOR;Arena/XBox/First Person Shooter/Halo 2;12;0;0;0;
KAI_CLIENT_SUB_VECTOR;Arena/XBox;13;0;0;0;
```

### List players in the current arena/chat

For General Chat, verified via `KAI_CLIENT_GETSTATE`:

```sh
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_GETSTATE	"
curl -sS -X POST "http://127.0.0.1:34522/connector/poll?sessionid=$SID"   | python3 -c 'import sys,urllib.parse; print("
".join(line for line in urllib.parse.unquote(sys.stdin.read()).split("\x01") if "JOINS_CHAT" in line or "JOINS_VECTOR" in line))'
```

In an arena, expect `KAI_CLIENT_JOINS_VECTOR;<kaitag>;` plus ping/device updates after entering that arena.

### Send a chat message

Inferred from JS; user-visible, not invoked during recon:

```sh
MSG='hello from the connector API'
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_CHAT	$MSG	"
```

### Kick a player

Inferred from moderator JS; destructive/user-visible, not invoked during recon:

```sh
PLAYER='<kaitag>'
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_ARENA_KICK	$PLAYER	"
```

Related moderator commands from JS: `KAI_CLIENT_ARENA_BAN	<kaitag>	`, `KAI_CLIENT_CHAT_LOCK	<kaitag>	`, and `KAI_CLIENT_CHAT	/orb disconnect <kaitag>`.

### Get current state

Verified:

```sh
curl -sS -X POST http://127.0.0.1:34522/connector/command   --data-urlencode "sessionid=$SID"   --data-urlencode "command=KAI_CLIENT_GETSTATE	"
curl -sS -X POST "http://127.0.0.1:34522/connector/poll?sessionid=$SID"   | python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()).replace("\x01","\n"))'
```

### Detach

```sh
curl -sS -X POST "http://127.0.0.1:34522/connector/detach?sessionid=$SID"
```

## 7. Open questions and gaps

- Exact argument lists for strings-only handlers such as APP_SPECIFIC, CAPS, DISCOVER, NATTEST, SPECIFIC_COUNT, TAKEOVER, and ARENA_BREAK_STREAM remain unknown.
- KAI_CLIENT_GET_VECTORS with an empty arena path returned no events, while `Arena` returned top-level arena entries; root path semantics may be special-cased.
- The WebUI references KAI_CLIENT_CHAT_LOCK, KAI_CLIENT_DISMISS_NOTIFICATION, and KAI_CLIENT_SKIN although these were not present as `_uihandler` tokens in the collected strings list.
- No destructive/user-visible commands were probed: chat, private message, kick, ban, invite, friend/contact mutation, create vector, logout, login, and orb selection were inferred only.
- The /connector/saveconfig format is visible in JS as HTML form key/value POSTs but was not changed or verified because that would alter engine configuration.

## Verification notes

Live probes used one connector session for the first batch and one follow-up session for `KAI_CLIENT_GET_VECTORS	Arena	`; both were detached. Verified commands were read-only or UI-context-only:

- `KAI_CLIENT_GETSTATE	`
- `KAI_CLIENT_ORBS_AVAILABLE	`
- `KAI_CLIENT_GET_VECTORS		` and `KAI_CLIENT_GET_VECTORS	Arena	`
- `KAI_CLIENT_GET_METRICS	`
- `KAI_CLIENT_GET_NOTIFICATIONS	`
- `KAI_CLIENT_CHATMODE	General Chat	`

No xlink container restart, config write, chat send, login/logout, kick/ban, invite, contact mutation, private arena creation, or orb selection was performed.
