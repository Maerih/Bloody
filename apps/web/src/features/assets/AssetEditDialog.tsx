import { AssetKind, Criticality, type Asset } from "@bloody/contracts";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useCreateAsset, useUpdateAsset } from "../../api/hooks";
import type { UpdateAssetInput } from "../../api/types";
import { Button } from "../../components/Button";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Dialog } from "../../components/Overlay";
import { humanize } from "../../lib/format";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

export function parseList(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean))];
}

export function isIpAddress(value: string): boolean {
  return IPV4.test(value) || (value.includes(":") && IPV6.test(value) && value.length <= 39);
}

export interface AssetFormErrors {
  name?: string;
  hostname?: string;
  ips?: string;
  tags?: string;
  organizationId?: string;
}

export function validateAssetForm(f: { name: string; hostname: string; ips: string; tags: string; organizationId: string | null; requireOrg: boolean }): AssetFormErrors {
  const errors: AssetFormErrors = {};
  if (!f.name.trim()) errors.name = "Name is required";
  else if (f.name.trim().length > 300) errors.name = "At most 300 characters";
  if (f.hostname.trim() && !/^[A-Za-z0-9.\-_]{1,255}$/.test(f.hostname.trim())) errors.hostname = "Letters, digits, dots, dashes and underscores only";
  const bad = parseList(f.ips).find((ip) => !isIpAddress(ip));
  if (bad) errors.ips = `Not an IP address: ${bad}`;
  else if (parseList(f.ips).length > 64) errors.ips = "At most 64 addresses";
  const tags = parseList(f.tags);
  if (tags.length > 64) errors.tags = "At most 64 tags";
  else if (tags.some((t) => t.length > 64)) errors.tags = "Tags are at most 64 characters";
  if (f.requireOrg && !f.organizationId) errors.organizationId = "Choose an organization";
  return errors;
}

/**
 * Create an asset, or edit one (criticality — crown-jewel designation drives attack-path and
 * exposure prioritization — ownership, exposure and tags). Changes are audited server-side.
 */
export function AssetEditDialog({ asset, onClose, onSaved }: { asset: Asset | null; onClose: () => void; onSaved?: (a: Asset) => void }) {
  const defaultOrg = useDefaultOrganization("asset:write");
  const create = useCreateAsset();
  const update = useUpdateAsset(asset?.id ?? "");
  const m = asset ? update : create;
  const [orgId, setOrgId] = useState<string | null>(asset?.organizationId ?? defaultOrg);
  const [kind, setKind] = useState<Asset["kind"]>(asset?.kind ?? "server");
  const [name, setName] = useState(asset?.name ?? "");
  const [hostname, setHostname] = useState(asset?.hostname ?? "");
  const [ips, setIps] = useState(asset?.ipAddresses.join(", ") ?? "");
  const [os, setOs] = useState(asset?.os ?? "");
  const [criticality, setCriticality] = useState<Asset["criticality"]>(asset?.criticality ?? "medium");
  const [internetFacing, setInternetFacing] = useState(asset?.internetFacing ?? false);
  const [owner, setOwner] = useState(asset?.owner ?? "");
  const [tags, setTags] = useState(asset?.tags.join(", ") ?? "");
  const [submitted, setSubmitted] = useState(false);
  const errors = validateAssetForm({ name, hostname, ips, tags, organizationId: orgId, requireOrg: !asset });
  const err = (k: keyof AssetFormErrors) => (submitted ? (errors[k] ?? null) : null);

  const submit = () => {
    setSubmitted(true);
    if (Object.keys(errors).length > 0) return;
    const body: UpdateAssetInput = {
      kind,
      name: name.trim(),
      hostname: hostname.trim() || null,
      ipAddresses: parseList(ips),
      os: os.trim() || null,
      criticality,
      internetFacing,
      owner: owner.trim() || null,
      tags: parseList(tags),
    };
    if (asset) update.mutate(body, { onSuccess: (a) => (onSaved?.(a), onClose()) });
    else create.mutate({ ...body, organizationId: orgId!, kind, name: name.trim(), ipAddresses: body.ipAddresses ?? [], criticality, internetFacing, tags: body.tags ?? [] }, { onSuccess: (a) => (onSaved?.(a), onClose()) });
  };

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={asset ? `Edit ${asset.hostname ?? asset.name}` : "Add asset"}
      description="Criticality drives prioritization: crown jewels anchor attack-path analysis and exposure scoring."
      footer={
        <>
          {m.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(m.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={m.isPending}>
            {asset ? "Save asset" : "Add asset"}
          </Button>
        </>
      }
    >
      <form
        className="grid grid-cols-1 gap-3 md:grid-cols-2"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {!asset ? (
          <Field label="Organization" required error={err("organizationId")} className="md:col-span-2">
            {(p) => <OrganizationSelect {...p} value={orgId} onChange={setOrgId} permission="asset:write" />}
          </Field>
        ) : null}
        <Field label="Name" required error={err("name")}>
          {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value)} maxLength={300} autoFocus />}
        </Field>
        <Field label="Kind" required>
          {(p) => (
            <Select {...p} value={kind} onChange={(e) => setKind(e.target.value as Asset["kind"])}>
              {AssetKind.options.map((k) => (
                <option key={k} value={k}>
                  {humanize(k)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Hostname" error={err("hostname")}>
          {(p) => <Input {...p} value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="dc01.corp.example" />}
        </Field>
        <Field label="IP addresses" error={err("ips")} hint="Comma or space separated">
          {(p) => <Input {...p} value={ips} onChange={(e) => setIps(e.target.value)} placeholder="10.0.0.10, 2001:db8::10" />}
        </Field>
        <Field label="Criticality" required hint="Crown jewel = business-critical (domain controllers, customer data, payment systems).">
          {(p) => (
            <Select {...p} value={criticality} onChange={(e) => setCriticality(e.target.value as Asset["criticality"])}>
              {Criticality.options.map((c) => (
                <option key={c} value={c}>
                  {humanize(c)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Operating system">
          {(p) => <Input {...p} value={os} onChange={(e) => setOs(e.target.value)} maxLength={200} />}
        </Field>
        <Field label="Owner">
          {(p) => <Input {...p} value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={200} placeholder="Team or person accountable" />}
        </Field>
        <Field label="Tags" error={err("tags")} hint="Comma separated, e.g. pci, decoy">
          {(p) => <Textarea {...p} value={tags} onChange={(e) => setTags(e.target.value)} rows={1} />}
        </Field>
        <Checkbox label="Internet-facing" checked={internetFacing} onChange={(e) => setInternetFacing(e.target.checked)} className="md:col-span-2" />
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
