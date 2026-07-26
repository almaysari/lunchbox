// Connector contract — the ONLY layer that talks to a mail provider.
// The database, sync pipeline and UI are provider-agnostic; adding
// Microsoft 365 or Gmail later means adding one file here.
//
// All connectors are READ-ONLY: they must never modify, move, delete,
// mark-as-read, forward or send anything on the provider side.
//
// interface Connector {
//   // proven capabilities for this mailbox ({folders, messages, attachments, sent})
//   capabilities(): object
//   // list folders: [{ providerFolderId, name, type }]
//   listFolders(): Promise<Folder[]>
//   // one page of message headers, oldest-page cursor semantics owned by caller:
//   //   [{ providerMessageId, rfcMessageId, threadId, from, fromName, to, cc,
//   //      subject, snippet, receivedAt, hasAttachments, direction }]
//   listMessages(folder, { start, limit }): Promise<Message[]>
//   // full body (html or text) for one message
//   getBody(folder, providerMessageId): Promise<string|null>
//   // [{ providerAttachmentId, name, size, mime }]
//   listAttachments(folder, providerMessageId): Promise<Attachment[]>
//   // raw bytes
//   downloadAttachment(folder, providerMessageId, providerAttachmentId): Promise<Buffer>
// }
//
// Strategies are switchable per mailbox WITHOUT data loss: messages are keyed
// to the platform mailbox id + dedup hash, never to the connector that
// imported them.
module.exports = {};
