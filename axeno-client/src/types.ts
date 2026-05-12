export interface InviteCode {
  id: string;
  code: string;
  createdAt: number; // Unix ms
}

export interface Contact {
  id: string;
  alias?: string;            // user-settable local label; initials fall back to first 2 chars of id
  lastReadAt: number | null; // Unix ms of last read received message; null = never
  serverChoice?: ServerChoice;
}

export interface Message {
  id: string;        // UUID — globally unique, safe for retry / out-of-order delivery
  mine: boolean;
  text: string;
  timestamp: number; // Unix ms
}

export interface PrivateServer {
  id: string;
  name: string;
  onion: string;
}

export type ServerChoice =
  | { kind: "official" }
  | { kind: "private"; serverId: string };

export interface AppSettings {
  defaultServer: ServerChoice;
  privateServers: PrivateServer[];
  inviteCodes: InviteCode[];
  readReceipts: boolean;
  defaultDisappearingMessages: number;
  notificationsEnabled: boolean;
  notificationShowPreview: boolean;
  notificationShowSender: boolean;
  sendOnEnter: boolean;
  messageTextSize: "small" | "medium" | "large";
  // messageRetentionDays removed: retention is a per-server config, not a client setting
}

export const defaultSettings: AppSettings = {
  defaultServer: { kind: "official" },
  privateServers: [],
  inviteCodes: [],
  readReceipts: true,
  defaultDisappearingMessages: 0,
  notificationsEnabled: true,
  notificationShowPreview: false,
  notificationShowSender: false,
  sendOnEnter: true,
  messageTextSize: "medium",
};
