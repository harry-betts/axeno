import { useState } from "react";
import Sidebar from "./components/Sidebar/Sidebar";
import ChatView from "./components/ChatView/ChatView";
import Settings from "./components/Settings/Settings";
import ChatSettings from "./components/ChatSettings/ChatSettings";
import AddContact from "./components/AddContact/AddContact";
import Onboarding from "./components/Onboarding/Onboarding";
import VerifyIdentity from "./components/VerifyIdentity/VerifyIdentity";
import { Contact, AppSettings, ServerChoice, defaultSettings } from "./types";
import { mockContacts, mockMessages } from "./mockData";
import "./App.css";

function computeInitials(name: string): string {
  return name.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

export default function App() {
  const [identityCreated, setIdentityCreated] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [contacts, setContacts] = useState<Contact[]>(mockContacts);
  const [activeContactId, setActiveContactId] = useState("ax7f2c");
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);

  const [showSettings, setShowSettings]     = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showChatSettings, setShowChatSettings] = useState(false);
  const [showVerify, setShowVerify]         = useState(false);

  if (!identityCreated) {
    return <Onboarding onComplete={(name) => { setDisplayName(name); setIdentityCreated(true); }} />;
  }

  const active = contacts.find(c => c.id === activeContactId)!;

  const updateContactServer = (id: string, server: ServerChoice) => {
    setContacts(prev =>
      prev.map(c => (c.id === id ? { ...c, serverChoice: server } : c))
    );
  };

  return (
    <div className="app-root">
      <Sidebar
        contacts={contacts}
        allMessages={mockMessages}
        activeContactId={activeContactId}
        onSelectContact={setActiveContactId}
        onOpenAddContact={() => setShowAddContact(true)}
        onOpenSettings={() => setShowSettings(true)}
        myInitials={computeInitials(displayName)}
        myDisplayName={displayName}
      />

      <ChatView
        contact={active}
        messages={mockMessages[active.id] || []}
        onOpenChatSettings={() => setShowChatSettings(true)}
      />

      {showSettings && (
        <Settings
          settings={settings}
          onChange={setSettings}
          displayName={displayName}
          onChangeName={setDisplayName}
          onClose={() => setShowSettings(false)}
        />
      )}

      {showAddContact && (
        <AddContact onClose={() => setShowAddContact(false)} />
      )}

      {showChatSettings && (
        <ChatSettings
          contact={active}
          settings={settings}
          onClose={() => setShowChatSettings(false)}
          onOpenVerify={() => { setShowChatSettings(false); setShowVerify(true); }}
          onUpdateContactServer={updateContactServer}
        />
      )}

      {showVerify && (
        <VerifyIdentity contact={active} onClose={() => setShowVerify(false)} />
      )}
    </div>
  );
}
