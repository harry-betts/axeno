import { Contact, Message } from "./types";

export const mockContacts: Contact[] = [
  { id: "ax7f2c", initials: "AX", preview: "sounds good to me",       time: "now",   unread: 0 },
  { id: "kp9a1d", initials: "KP", preview: "did you get my message",  time: "14:02", unread: 2 },
  { id: "r3mx8b", initials: "R3", preview: "ok",                      time: "09:41", unread: 0 },
  { id: "fn4e9c", initials: "FN", preview: "meeting at 6?",           time: "Mon",   unread: 0 },
  { id: "zq1b7f", initials: "ZQ", preview: "encrypted file attached", time: "Sun",   unread: 0 },
];

export const mockMessages: Record<string, Message[]> = {
  ax7f2c: [
    { id: 1, mine: false, text: "hey, did you get the updated keys I sent over?",                    time: "13:41" },
    { id: 2, mine: false, text: "want to make sure the ratchet state is synced before we proceed",   time: "13:41" },
    { id: 3, mine: true,  text: "yeah got them, verified the fingerprint too",                        time: "13:44" },
    { id: 4, mine: true,  text: "sounds good to me",                                                  time: "13:44" },
  ],
  kp9a1d: [
    { id: 1, mine: false, text: "did you get my message", time: "14:02" },
    { id: 2, mine: false, text: "?", time: "14:02" },
  ],
  r3mx8b: [
    { id: 1, mine: true,  text: "ok", time: "09:41" },
  ],
  fn4e9c: [
    { id: 1, mine: false, text: "meeting at 6?", time: "Mon" },
  ],
  zq1b7f: [
    { id: 1, mine: false, text: "encrypted file attached", time: "Sun" },
  ],
};

export const mockMyIdentity = {
  initials: "HB",
  fingerprint: "hb3f9c2a8d4e1b7f5c8a2d6e9b1f4c7a3e5d8b2c6f9a1d4e7b3c8f5a2d9e6b1c4a",
  shortKey: "hb3f9...a2c1",
};
