CREATE TABLE "AgentCheckins" (
	"agent_uuid"	TEXT NOT NULL,
	"target_ipv4_address"	TEXT NOT NULL,
	"time_unix"	INTEGER NOT NULL,
	PRIMARY KEY("agent_uuid","target_ipv4_address","time_unix"),
	FOREIGN KEY("agent_uuid") REFERENCES "Agents"("agent_uuid"),
	FOREIGN KEY("target_ipv4_address") REFERENCES "TargetsInScope"("target_ipv4_address") ON UPDATE CASCADE
);

CREATE TABLE "Agents" (
	"agent_uuid"	TEXT NOT NULL UNIQUE,
	"team_id"	INTEGER NOT NULL,
	"server_private_key"	TEXT NOT NULL UNIQUE,
	"agent_public_key"	TEXT NOT NULL UNIQUE,
	"created_date_unix"	INTEGER NOT NULL,
	"root_date_unix"	INTEGER,
	FOREIGN KEY("team_id") REFERENCES "Teams"("team_id"),
	PRIMARY KEY("agent_uuid")
);

CREATE TABLE "TargetsInScope" (
	"target_ipv4_address"	TEXT NOT NULL UNIQUE,
	"value"	INTEGER NOT NULL DEFAULT 1,
	PRIMARY KEY("target_ipv4_address")
);

CREATE TABLE "Teams" (
	"team_id"	INTEGER	NOT NULL UNIQUE,
	"name"	TEXT NOT NULL UNIQUE,
	"password_hash"	TEXT NOT NULL,
	"created_date_unix"	INTEGER NOT NULL,
	PRIMARY KEY("team_id" AUTOINCREMENT)
)