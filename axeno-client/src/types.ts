export interface Contact {
  id: string;
  initials: string;
  preview: string;
  time: string;
  unread: number;
  serverChoice?: ServerChoice;
}

export interface Message {
  id: number;
  mine: boolean;
  text: string;
  time: string;
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
  readReceipts: boolean;
  defaultDisappearingMessages: number;
  notificationsEnabled: boolean;
  notificationShowPreview: boolean;
  notificationShowSender: boolean;
  sendOnEnter: boolean;
  messageTextSize: "small" | "medium" | "large";
  messageRetentionDays: number;
}

export const defaultSettings: AppSettings = {
  defaultServer: { kind: "official" },
  privateServers: [],
  readReceipts: true,
  defaultDisappearingMessages: 0,
  notificationsEnabled: true,
  notificationShowPreview: false,
  notificationShowSender: false,
  sendOnEnter: true,
  messageTextSize: "medium",
  messageRetentionDays: 30,
};
