import type { AppRole } from "@/types/api";

/**
 * Build a clean role with only the fields applicable to its current `type`.
 *
 * Why: the wizard keeps all credential fields in one form even when the user
 * navigates back and switches type (e.g. picks `s3_compatible`, fills keys,
 * goes back, switches to `default`). Spreading `form.values` straight into the
 * config would persist stale `access_key_id`/`secret_access_key`/`endpoint_url`
 * into a default role's JSON. Not a security leak (the file already holds
 * secrets) but config pollution that confuses ops and review.
 */
export function stripIrrelevantFields(role: AppRole): AppRole {
  const base: AppRole = {
    name: role.name,
    type: role.type,
    description: role.description,
    allowed_buckets: role.allowed_buckets,
  };
  switch (role.type) {
    case "default":
      return base;
    case "profile":
      return { ...base, profile_name: role.profile_name };
    case "assume_role":
      return { ...base, role_arn: role.role_arn };
    case "credentials":
      return {
        ...base,
        access_key_id: role.access_key_id,
        secret_access_key: role.secret_access_key,
        region: role.region,
      };
    case "s3_compatible":
      return {
        ...base,
        access_key_id: role.access_key_id,
        secret_access_key: role.secret_access_key,
        region: role.region,
        endpoint_url: role.endpoint_url,
        use_ssl: role.use_ssl,
        verify_ssl: role.verify_ssl,
        addressing_style: role.addressing_style,
      };
  }
}
