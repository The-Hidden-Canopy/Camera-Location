-- Keep import idempotency keys bound to the evidence payload that first used them.
ALTER TABLE network_import_receipts ADD COLUMN records_hash TEXT;
