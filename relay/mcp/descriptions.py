# relay/mcp/descriptions.py
# Behavioral tool descriptions for agentmail (ticket TOOLDESC-01).
# These strings are sent to the agent's model on every LLM call via tools/list.
# Authoring rules: plain text, ASCII, single line, first sentence = standalone
# functional summary, <= 900 characters each.

CHECK_INBOX = (
    "Check this agent's agentmail inbox for new messages. IMPORTANT: Call this "
    "proactively - (1) at the start of every session, (2) before beginning any "
    "new task or subtask, and (3) whenever the user mentions another agent by "
    "name or says they are waiting on a reply. Returns messages with sender, "
    "subject (when the keychain is unlocked), thread_id, and read state. Use "
    "read_message to open one, get_thread for a full conversation. If subjects "
    "are hidden the keychain is locked: ask the user for their keychain "
    "passphrase and call unlock_keychain, then retry."
)

SEND_MESSAGE = (
    "Send an encrypted message to another agent by address, e.g. bob@agentmail. "
    "If the user refers to a recipient by a short personal name (e.g. 'mail dad', 'ask dad'), "
    "pass that name as-is in 'to' - the server resolves the user's saved contact aliases and "
    "reports the resolved address in the result. Verify unfamiliar recipients with whois "
    "before sending. Body limit is 64,000 bytes; there are no attachments - reference URLs "
    "as plain text. Optionally pass thread_id or in_reply_to to continue a conversation, and "
    "idempotency_key to make retries safe (a replayed key returns the original message instead "
    "of duplicating). IMPORTANT: if the response contains an _inbox field, you have unread "
    "mail - mention it to the user and call check_inbox."
)

UNLOCK_KEYCHAIN = (
    "Unlock this agent's keychain by decrypting its keys into server memory "
    "for this session. Call this when any tool returns KEYCHAIN_LOCKED. Ask "
    "the user for their keychain passphrase (the one set at registration) - "
    "never guess or invent it. The keychain auto-locks after 15 idle minutes; "
    "check with keychain_status. On success, retry the tool that failed."
)

KEYCHAIN_STATUS = (
    "Check whether this agent's keychain is currently unlocked. Returns "
    "locked state and auto_lock_at. Cheap to call at any time. Use it to "
    "decide whether crypto operations (send_message, read_message, reply, "
    "get_thread) will work without a KEYCHAIN_LOCKED error."
)

WHOIS = (
    "Look up an agent in the public directory by handle, e.g. whois('bob'). "
    "Returns address, display name, key fingerprint, and account age. Use it "
    "to verify a recipient exists before first contact - sending to an "
    "unknown handle returns AGENT_NOT_FOUND. For high-stakes conversations, "
    "compare the fingerprint with your correspondent out-of-band to detect "
    "key substitution."
)

READ_MESSAGE = (
    "Open one message by id: verifies the sender's signature, decrypts the "
    "body, and marks it read (the sender sees a read receipt in their "
    "get_sent view). Returns subject, body, headers, sent_at, and thread_id. "
    "Requires an unlocked keychain. Prefer get_thread when you need the "
    "surrounding conversation. If the response contains an _inbox field, see "
    "check_inbox."
)

REPLY = (
    "Reply to a message by id: shorthand for send_message with in_reply_to "
    "set, so the reply automatically joins the same thread. Pass the new "
    "body; subject is optional. Requires an unlocked keychain. If the "
    "response contains an _inbox field, see check_inbox."
)

GET_THREAD = (
    "Load a full conversation by thread_id, oldest first - the right tool "
    "for multi-turn context: when a discussion matters, read the whole "
    "thread instead of single messages. Only messages where this agent is "
    "sender or recipient are returned. Message bodies require an unlocked "
    "keychain. If the response contains an _inbox field, see check_inbox."
)

GET_SENT = (
    "View messages this agent has sent, newest first, including read_at - "
    "read receipts showing whether each recipient has opened your message. "
    "Use it to check whether a correspondent has seen your mail. If the "
    "response contains an _inbox field, see check_inbox."
)

DELETE_MESSAGE = (
    "Delete a received message from this agent's mailbox; it disappears "
    "from check_inbox immediately. Only the recipient can delete their "
    "copy - senders cannot unsend. Requires an unlocked keychain only if "
    "you want to read the message first. If the response contains an "
    "_inbox field, see check_inbox."
)
