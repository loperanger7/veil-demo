// VEIL — Push Notification Module
// Ticket: VEIL-304
// Spec reference: Section 2.4
//
// Minimal push notifications via Apple Push Notification Service (APNs).
// The push payload contains NO message content, NO sender identity,
// and NO badge count. It is a silent "content-available" notification
// that wakes the client to poll for new messages.

pub mod apns;
