import { Contact, Message } from "./types";

const T = Date.now();
const ago = (ms: number) => T - ms;
const M = 60_000;
const H = 3_600_000;
const D = 86_400_000;

const AX_LAST = ago(2 * H + 26 * M);
const KP_LAST = ago(2 * H + 8 * M);
const R3_LAST = ago(5 * H + 30 * M);
const FN_LAST = ago(2 * D);
const ZQ_LAST = ago(3 * D);

export const mockContacts: Contact[] = [
  { id: "ax7f2c", lastReadAt: AX_LAST + 1_000 }, // all read
  { id: "kp9a1d", lastReadAt: null },              // 2 unread
  { id: "r3mx8b", lastReadAt: null },              // only sent messages → unread = 0
  { id: "fn4e9c", lastReadAt: FN_LAST + 1_000 },  // read
  { id: "zq1b7f", lastReadAt: ZQ_LAST + 1_000 },  // read
];

export const mockMessages: Record<string, Message[]> = {
  ax7f2c: [
    { id: "ax-1", mine: false, text: "hey, did you get the updated keys I sent over?",                    timestamp: ago(2 * H + 30 * M) },
    { id: "ax-2", mine: false, text: "want to make sure the ratchet state is synced before we proceed",   timestamp: ago(2 * H + 29 * M) },
    { id: "ax-3", mine: true,  text: "yeah got them, verified the fingerprint too",                        timestamp: ago(2 * H + 27 * M) },
    { id: "ax-4", mine: true,  text: "sounds good to me",                                                  timestamp: AX_LAST },
  ],
  kp9a1d: [
    { id: "kp-1", mine: false, text: "did you get my message", timestamp: ago(2 * H + 9 * M) },
    { id: "kp-2", mine: false, text: "?",                      timestamp: KP_LAST },
  ],
  r3mx8b: [
    { id: "r3-1", mine: true, text: "ok", timestamp: R3_LAST },
  ],
  fn4e9c: [
    { id: "fn-1", mine: false, text: "meeting at 6?", timestamp: FN_LAST },
  ],
  zq1b7f: [
    { id: "zq-1", mine: false, text: "encrypted file attached", timestamp: ZQ_LAST },
  ],
};
