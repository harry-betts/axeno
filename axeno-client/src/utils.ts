import { Contact, Message } from "./types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function contactDisplayName(contact: Contact): string {
  const name = contact.displayName?.trim();
  return name || "Unknown contact";
}

export function contactInitials(contact: Contact): string {
  const name = contactDisplayName(contact);
  return name.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

export function formatMessageTime(timestamp: number): string {
  const now = new Date();
  const date = new Date(timestamp);

  if (now.toDateString() === date.toDateString()) {
    return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
  }

  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (yesterday.toDateString() === date.toDateString()) return "Yesterday";

  if (now.getTime() - timestamp < 7 * 86_400_000) return DAYS[date.getDay()];

  return `${date.getDate()} ${MONTHS[date.getMonth()]}`;
}

export function lastMessage(messages: Message[]): Message | undefined {
  if (!messages.length) return undefined;
  return messages.reduce((a, b) => (a.timestamp > b.timestamp ? a : b));
}

function unreadComparisonTime(message: Message): number {
  // Inbound message.timestamp is chosen by the sender. For unread state we need
  // the local receiver clock, otherwise two localhost clients with slightly
  // different clocks can leave a badge stuck forever after mark-as-read.
  return message.receivedAtMs ?? message.timestamp;
}

export function unreadCount(messages: Message[], lastReadAt: number | null): number {
  const inbound = messages.filter(m => !m.mine);
  if (lastReadAt === null) return inbound.length;
  return inbound.filter(m => unreadComparisonTime(m) > lastReadAt).length;
}
