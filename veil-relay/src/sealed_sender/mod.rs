// VEIL — Sealed Sender Module
// Ticket: VEIL-302
// Spec reference: Section 4.2
//
// The sealed sender system ensures the relay server cannot determine
// who sent a message. The envelope's sealed_sender field is opaque
// ciphertext that only the recipient can decrypt.
//
// Server invariants:
//   - Never inspect sealed_sender payload
//   - Never log sender identity
//   - Never correlate sender IP with message
//   - Route solely on (registration_id, device_id)

pub mod envelope;
