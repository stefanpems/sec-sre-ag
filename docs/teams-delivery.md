# Sending Messages through Microsoft Teams

## Problem Context

The Teams connector's `PostMessageToConversation` tool declares only two parameters in its schema: `poster` and `location`. The `body` parameter, which contains the recipient and message content, is **not declared in the schema**, but the MCP server **accepts it when passed as an additional parameter**. If the agent omits it, the server returns errors such as `"Message body is missing."` or `"Group ID does not exist."`.

## Correct Pattern — Post to a Teams Channel

```json
{
  "poster": "User",
  "location": "Channel",
  "body": {
    "recipient": {
      "groupId": "<team GUID, for example 712f17bc-f9c4-4654-b130-805466bc7105>",
      "channelId": "<channel ID, for example 19:pCeY...@thread.tacv2>"
    },
    "messageBody": "<HTML message content>"
  }
}
```

**Extracting `groupId` and `channelId` from a Teams URL:**

Given a URL such as `https://teams.cloud.microsoft/l/channel/19%3A...%40thread.tacv2/General?groupId=712f17bc-...&tenantId=...`:

- `groupId`: the `groupId` query parameter
- `channelId`: the URL-decoded path segment after `/channel/`, such as `19:pCeY...@thread.tacv2`

## Correct Pattern — Post to a Group Chat

```json
{
  "poster": "User",
  "location": "Group chat",
  "body": {
    "recipient": "<chat ID, for example 19:abc123...@thread.v2>",
    "messageBody": "<HTML message content>"
  }
}
```

**Note:** For group chats, `recipient` is a **string** containing the chat ID, not an object.

## Correct Pattern — Direct Message through Flow Bot

```json
{
  "poster": "Flow bot",
  "location": "Chat with Flow bot",
  "body": {
    "recipient": {
      "to": "<recipient email address or Entra object ID>"
    },
    "messageBody": "<HTML message content>"
  }
}
```

## Correct Pattern — Message to Self (Notes)

The `PostMessageToSelf` tool has a different schema and works directly:

```json
{
  "body": {
    "body": {
      "content": "<HTML message content>",
      "contentType": "html"
    }
  }
}
```

## CRITICAL Rules

| Rule | Detail |
|------|--------|
| **Always pass `body`** | The MCP server accepts it even though the tool schema does not declare it. Without `body`, the server returns errors. |
| **`location` does not contain IDs** | `location` is a CATEGORY (`"Channel"`, `"Group chat"`, or `"Chat with Flow bot"`), not an identifier. Put IDs in `body.recipient`. |
| **`messageBody` supports HTML** | Content may contain `<strong>`, `<br/>`, `<p>`, `<a>`, `<table>`, and other supported HTML elements. |
| **Send once** | If the tool returns a successful response containing `id`, `createdDateTime`, or equivalent confirmation, the message was sent. Do NOT send it again. |

## Common Errors and Diagnosis

| Error | Cause | Solution |
|-------|-------|----------|
| `"Message body is missing."` | The call omitted the `body` parameter | Add `body` with `recipient` and `messageBody` |
| `"Group ID does not exist."` | `body.recipient.groupId` is missing or incorrect | Verify the team GUID and include it in `body.recipient` |
| Message sent with empty content | `messageBody` is missing from `body` | Add `messageBody` with the HTML content |

## Teams Connector Tools to Enable

Enable these tools on the agent's Teams connector for full functionality:

- **Post Message in a Chat or Channel** (`PostMessageToConversation`) for channels and group chats
- **Post Message to myself** (`PostMessageToSelf`) for the personal Notes chat
