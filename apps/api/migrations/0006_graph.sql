-- Security Graph storage (contract of @bloody/engines SqlGraphStore / GRAPH_SCHEMA_SQL).

CREATE TABLE graph_nodes (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  kind             text NOT NULL,
  key              text NOT NULL CHECK (length(key) BETWEEN 1 AND 2048),
  label            text NOT NULL,
  props            jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX graph_nodes_natural_key ON graph_nodes (tenant_id, org_key(organization_id), kind, key);
CREATE INDEX graph_nodes_kind_key ON graph_nodes (tenant_id, kind, key text_pattern_ops);
CREATE INDEX graph_nodes_label ON graph_nodes (tenant_id, lower(label) text_pattern_ops);
CREATE INDEX graph_nodes_props ON graph_nodes USING gin (props jsonb_path_ops);
CREATE TRIGGER graph_nodes_updated_at BEFORE UPDATE ON graph_nodes FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE graph_edges (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  kind             text NOT NULL,
  from_id          uuid NOT NULL REFERENCES graph_nodes (id) ON DELETE CASCADE,
  to_id            uuid NOT NULL REFERENCES graph_nodes (id) ON DELETE CASCADE,
  props            jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, from_id, kind, to_id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX graph_edges_from ON graph_edges (tenant_id, from_id, kind);
CREATE INDEX graph_edges_to ON graph_edges (tenant_id, to_id, kind);
CREATE TRIGGER graph_edges_updated_at BEFORE UPDATE ON graph_edges FOR EACH ROW EXECUTE FUNCTION set_updated_at();
