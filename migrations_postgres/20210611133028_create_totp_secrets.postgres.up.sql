-- auth.totp_secrets definition

CREATE TABLE IF NOT EXISTS auth.totp_secrets (
    instance_id uuid NULL,
    id bigserial NOT NULL,
    user_id uuid NOT NULL,
    encrypted_secret text NULL,
    otp_last_requested_at timestamptz NULL,
    created_at timestamptz NULL,
	updated_at timestamptz NULL,
    CONSTRAINT totp_secrets_pkey PRIMARY KEY (id),
    CONSTRAINT user_id_fk FOREIGN KEY(user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
CREATE INDEX totp_secrets_instance_id_idx ON auth.totp_secrets USING btree (instance_id);
CREATE INDEX totp_secrets_instance_id_user_id_idx ON auth.totp_secrets USING btree (instance_id, user_id);
comment on table auth.totp_secrets is 'Auth: Store of totp secrets used to generate otp once they expire.';