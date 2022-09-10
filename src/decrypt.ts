import * as crypto from "crypto";
import { IContent, IEncryptedBackup, IKeyParams } from "./types";

export async function decrypt(
  password: string,
  backup: IEncryptedBackup
): Promise<IContent> {
  const backupInfo = parseBackupFile(backup);
  const key = await deriveKey(
    password,
    backupInfo.n,
    backupInfo.r,
    backupInfo.p,
    backupInfo.salt
  );
  const masterKey = decryptMasterKey(
    key,
    backupInfo.key,
    backupInfo.slotKeyParams
  );
  const plainText = decryptPayload(
    backupInfo.payload,
    masterKey,
    backupInfo.keyParams
  );
  return JSON.parse(plainText.toString());
}

function parseBackupFile(backup: IEncryptedBackup) {
  const slot = (() => {
    for (const slot of backup.header.slots) {
      if (slot.type === 1) return slot;
    }
    throw new Error("No password-encrypted slot found");
  })();

  return {
    n: slot.n,
    r: slot.r,
    p: slot.p,
    salt: Buffer.from(slot.salt, "hex"),
    key: Buffer.from(slot.key, "hex"),
    slotKeyParams: slot.key_params,
    keyParams: backup.header.params,
    payload: Buffer.from(backup.db, "base64"),
  };
}

function deriveKey(
  password: string,
  n: number,
  r: number,
  p: number,
  salt: Buffer
) {
  return new Promise<Buffer>((res, rej) => {
    crypto.scrypt(
      password,
      salt,
      32,
      { N: n, r, p, maxmem: 256 * n * r },
      (err, result) => (err ? rej(err) : res(result))
    );
  });
}

function decryptMasterKey(
  derivedKey: Buffer,
  encryptedKey: Buffer,
  keyParams: IKeyParams
) {
  const decrypt = crypto.createDecipheriv(
    "aes-256-gcm",
    derivedKey,
    Buffer.from(keyParams.nonce, "hex")
  );
  decrypt.setAuthTag(Buffer.from(keyParams.tag, "hex"));
  return Buffer.concat([decrypt.update(encryptedKey), decrypt.final()]);
}

function decryptPayload(
  payload: Buffer,
  masterKey: Buffer,
  keyParams: IKeyParams
) {
  const decrypt = crypto.createDecipheriv(
    "aes-256-gcm",
    masterKey,
    Buffer.from(keyParams.nonce, "hex")
  );
  decrypt.setAuthTag(Buffer.from(keyParams.tag, "hex"));
  return Buffer.concat([decrypt.update(payload), decrypt.final()]);
}
