# VenVia Core

Standalone PHP OOP ERP engine. No WordPress dependency on local servers. WordPress integration belongs to VenVia Web.

Status: migration foundation, not a release or a replacement for Core 0.3. The complete audited 0.3 source must be imported before functional equivalence can be claimed.

Desk installs the initial Core package. Control Center manages subsequent approved Core updates and all other PHP plugins, with staging, backup and rollback.

Required baseline: technical and operational administrators, local password authentication, administrator-controlled password reset and access revocation, technical administrator offline recovery key, initial setup, role authorization, APIs, plugin manager, backup, restore, staging and migration, approved GitHub updates, existing business functionality. Preserve actual source and test each capability.

Never commit configuration secrets, production data, private certificates, recovery keys or generated backups.

See docs/install-contract.md and tools/runtime-health.php. The health probe is a CLI diagnostic, not the Core itself.
