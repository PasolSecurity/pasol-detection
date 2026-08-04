# Local Reputation Store

The versioned JSON store contains bounded, schema-validated entries. Updates are written to a temporary file and atomically renamed. Expired or disabled entries are ignored; conflicting active entries produce `suspicious` evidence. Corrupt stores are rejected.
