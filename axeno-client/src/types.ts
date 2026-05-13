export interface InviteCode {
  id: string;
  code: string;
  createdAt: number;
}

export interface Contact {
  id: string;
  displayName?: string | null;
  lastReadAt: number | null;
  recipientId?: string;
  serverUrl?: string;
  serverId?: string;
  safetyNumber?: string;
  serverChoice?: ServerChoice;
  trustState?: string;
  verifiedAtMs?: number | null;
}


export interface Message {
  id: string;
  mine: boolean;
  text: string;
  timestamp: number;
  status?: string;
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

export interface BackendContact {
  id: string;
  display_name?: string | null;
  recipient_id: string;
  server_url: string;
  server_id: string;
  safety_number: string;
  identity_public_b64?: string;
  registration_id?: number;
  device_id?: number;
  delivery_token?: string;
  trust_state?: string;
  verified_at_ms?: number | null;
  local_route_id?: string | null;
  signed_prekey_id?: number;
  opk_id?: number | null;
  last_read_at?: number | null;
}

export interface BackendMessage {
  id: string;
  contact_id: string;
  mine: boolean;
  text: string;
  timestamp: number;
  received_at_ms?: number | null;
  status: string;
}

export interface MessagingSnapshot {
  my_recipient_id: string;
  contacts: BackendContact[];
  messages: Record<string, BackendMessage[]>;
}

export function contactFromBackend(c: BackendContact): Contact {
  return {
    id: c.id,
    displayName: c.display_name,
    lastReadAt: c.last_read_at ?? null,
    recipientId: c.recipient_id,
    serverUrl: c.server_url,
    serverId: c.server_id,
    safetyNumber: c.safety_number,
    trustState: c.trust_state,
    verifiedAtMs: c.verified_at_ms ?? null,
  };
}

export function messageFromBackend(m: BackendMessage): Message {
  return {
    id: m.id,
    mine: m.mine,
    text: m.text,
    timestamp: m.timestamp,
    status: m.status,
  };
}
