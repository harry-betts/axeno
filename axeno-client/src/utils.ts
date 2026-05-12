import { Contact, Message } from "./types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function contactInitials(contact: Contact): string {
  if (contact.alias) {
    return contact.alias.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
  }
  return contact.id.slice(0, 2).toUpperCase();
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

export function unreadCount(messages: Message[], lastReadAt: number | null): number {
  if (lastReadAt === null) return messages.filter(m => !m.mine).length;
  return messages.filter(m => !m.mine && m.timestamp > lastReadAt).length;
}
